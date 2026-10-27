#!/usr/bin/env bash
# One-time provider setup: writes .env, secrets/upstream_api_key and the
# admin API key, starts Caddy + the proxy, and optionally creates the first
# client token.
#
#   scripts/setup.sh                                  # interactive
#   scripts/setup.sh --provider openrouter --domain auto --client alice --client-allow-ips 203.0.113.7
#   UPSTREAM_KEY=sk-... scripts/setup.sh --provider openai --domain llm.example.com --yes
#
# Run it from anywhere; it operates on the repository it lives in.
set -euo pipefail
cd "$(dirname "$0")/.."

usage() {
	cat <<'EOF'
Usage: scripts/setup.sh [options]

Upstream:
  --provider NAME          openai | openrouter | packy | custom (default: ask)
  --base-url URL           upstream base URL ending in /v1 (required for custom)
  --referer URL            OpenRouter attribution header HTTP-Referer (optional)
  --title NAME             OpenRouter attribution header X-Title (optional)

Deployment:
  --domain NAME            public hostname for HTTPS; "auto" = <public-ip>.sslip.io
  --host-network           use host networking (deploy/docker-compose.host.yml)
  --force                  overwrite an existing .env / key file
  --no-admin               don't enable the admin HTTP API (manage tokens only via scripts/keys.sh)

First client (optional):
  --client ID              create a client token with this id (printed once)
  --client-allow-ips LIST  only accept it from these IPs / CIDR ranges (comma-separated)
  --client-models LIST     restrict it to these models (comma-separated, prefix* ok)
  --client-concurrency N   max concurrent requests for it (default 64)

  --yes                    non-interactive; the upstream key is read from
                           $UPSTREAM_KEY or stdin
  -h, --help               show this help
EOF
}

PROVIDER="" BASE_URL="" REFERER="" TITLE="" DOMAIN="" HOST_NET=0 FORCE=0 YES=0
CLIENT="" CLIENT_MODELS="" CLIENT_CONC=64 CLIENT_IPS="" ADMIN=1
while [ $# -gt 0 ]; do
	case $1 in
	--provider) PROVIDER=$2; shift 2 ;;
	--base-url) BASE_URL=$2; shift 2 ;;
	--referer) REFERER=$2; shift 2 ;;
	--title) TITLE=$2; shift 2 ;;
	--domain) DOMAIN=$2; shift 2 ;;
	--host-network) HOST_NET=1; shift ;;
	--force) FORCE=1; shift ;;
	--client) CLIENT=$2; shift 2 ;;
	--client-models) CLIENT_MODELS=$2; shift 2 ;;
	--client-concurrency) CLIENT_CONC=$2; shift 2 ;;
	--client-allow-ips) CLIENT_IPS=$2; shift 2 ;;
	--no-admin) ADMIN=0; shift ;;
	--yes) YES=1; shift ;;
	-h | --help) usage; exit 0 ;;
	*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
	esac
done

say() { printf '\033[1m==> %s\033[0m\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
ask() { # ask VAR "prompt" [default]
	local __v
	[ "$YES" = 1 ] && die "$1 is required in --yes mode"
	read -r -p "$2${3:+ [$3]}: " __v
	printf -v "$1" '%s' "${__v:-${3:-}}"
}

command -v docker >/dev/null || die "docker is not installed"
docker compose version >/dev/null 2>&1 || die "docker compose v2 is required"
[ -f docker-compose.yml ] || die "run from the repository (docker-compose.yml not found)"
if [ -e .env ] && [ "$FORCE" != 1 ]; then
	die ".env already exists. Re-run with --force to replace it, or manage keys with scripts/keys.sh"
fi

# --- upstream provider ---------------------------------------------------
[ -n "$PROVIDER" ] || ask PROVIDER "Upstream provider (openai/openrouter/packy/custom)" openai
case $PROVIDER in
openai) BASE_URL=${BASE_URL:-https://api.openai.com/v1} ;;
openrouter) BASE_URL=${BASE_URL:-https://openrouter.ai/api/v1} ;;
packy) BASE_URL=${BASE_URL:-https://www.packyapi.com/v1} ;;
custom) [ -n "$BASE_URL" ] || ask BASE_URL "Upstream base URL (OpenAI-compatible, ends in /v1)" ;;
*) die "unknown provider '$PROVIDER'" ;;
esac
case $BASE_URL in https://*) ;; *) die "upstream base URL must use https" ;; esac

HEADERS=""
if [ "$PROVIDER" = openrouter ]; then
	[ -n "$REFERER" ] || [ "$YES" = 1 ] || ask REFERER "OpenRouter HTTP-Referer for app attribution (optional)" ""
	[ -n "$TITLE" ] || [ "$YES" = 1 ] || ask TITLE "OpenRouter X-Title for app attribution (optional)" ""
fi
[ -n "$REFERER" ] && HEADERS="HTTP-Referer=$REFERER"
[ -n "$TITLE" ] && HEADERS="${HEADERS:+$HEADERS;}X-Title=$TITLE"

# --- public hostname -------------------------------------------------------
if [ -z "$DOMAIN" ]; then
	ask DOMAIN "Public hostname for HTTPS (DNS must point here), or 'auto' for <ip>.sslip.io" auto
fi
if [ "$DOMAIN" = auto ]; then
	ip=$(curl -fsS -4 -m 10 https://api.ipify.org 2>/dev/null) || die "could not detect the public IPv4; pass --domain"
	DOMAIN="${ip//./-}.sslip.io"
	say "Using $DOMAIN (resolves to $ip)"
fi

# --- upstream key: stored as a file, never in .env -------------------------
KEY=${UPSTREAM_KEY:-}
unset UPSTREAM_KEY
if [ -z "$KEY" ]; then
	if [ "$YES" = 1 ] || [ ! -t 0 ]; then
		IFS= read -r KEY || true
	else
		read -r -s -p "Upstream API key for $PROVIDER (input hidden): " KEY
		echo >&2
	fi
fi
KEY=$(printf '%s' "$KEY" | tr -d '[:space:]')
[ -n "$KEY" ] || die "no upstream API key given"

install -d -m 700 secrets
if [ -e secrets/upstream_api_key ] && [ "$FORCE" != 1 ]; then
	die "secrets/upstream_api_key exists. Use --force, or rotate it with scripts/keys.sh upstream-key"
fi
SUDO=""
[ "$(id -u)" = 0 ] || { sudo -n true 2>/dev/null && SUDO=sudo; } || true
$SUDO rm -f secrets/upstream_api_key
(umask 077 && printf '%s' "$KEY" >secrets/upstream_api_key)
KEY=""
# The proxy runs as uid 65532 in the container. Prefer an owner-only file;
# otherwise make it world-readable inside the owner-only secrets/ directory.
if [ "$(uname -s)" = Linux ] && { [ -n "$SUDO" ] || [ "$(id -u)" = 0 ]; }; then
	$SUDO chown 65532:65532 secrets/upstream_api_key
	$SUDO chmod 0400 secrets/upstream_api_key
else
	chmod 0444 secrets/upstream_api_key
	say "No sudo: key file is 0444 inside the 0700 secrets/ directory"
fi

# --- admin API key ---------------------------------------------------------
# Lets the operator manage tokens over HTTPS (pxadmin / curl) instead of SSH.
ADMIN_KEY=""
if [ "$ADMIN" = 1 ]; then
	if [ -e secrets/admin_api_key ]; then
		say "Keeping the existing admin key (rotate it with scripts/keys.sh admin-key)"
	else
		ADMIN_KEY="sk-pxadmin-$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n')"
		(umask 077 && printf '%s' "$ADMIN_KEY" >secrets/admin_api_key)
		if [ "$(uname -s)" = Linux ] && { [ -n "$SUDO" ] || [ "$(id -u)" = 0 ]; }; then
			$SUDO chown 65532:65532 secrets/admin_api_key
			$SUDO chmod 0400 secrets/admin_api_key
		else
			chmod 0444 secrets/admin_api_key
		fi
	fi
fi

# --- .env ------------------------------------------------------------------
COMPOSE_FILES="docker-compose.yml:deploy/docker-compose.keyfile.yml"
[ "$HOST_NET" = 1 ] && COMPOSE_FILES="$COMPOSE_FILES:deploy/docker-compose.host.yml"
[ "$ADMIN" = 1 ] && COMPOSE_FILES="$COMPOSE_FILES:deploy/docker-compose.admin.yml"
(
	umask 077
	cat >.env <<EOF
# Generated by scripts/setup.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ). See .env.example for all options.
COMPOSE_FILE=$COMPOSE_FILES
PROXY_DOMAIN=$DOMAIN
UPSTREAM_BASE_URL=$BASE_URL
UPSTREAM_API_KEY_FILE=/run/secrets/upstream_api_key
LOG_FORMAT=json
EOF
	if [ -n "$HEADERS" ]; then printf 'UPSTREAM_HEADERS=%s\n' "$HEADERS" >>.env; fi
)
say "Wrote .env (provider: $PROVIDER, upstream: $BASE_URL)"

# --- start -------------------------------------------------------------------
say "Building and starting the stack"
docker compose up -d --build >&2   # stdout carries only the client token
for _ in $(seq 60); do
	docker compose exec -T proxy /oaiproxy healthcheck >/dev/null 2>&1 && break
	sleep 1
done
docker compose exec -T proxy /oaiproxy healthcheck >/dev/null 2>&1 || die "proxy did not become healthy; see: docker compose logs proxy"
fp=$(docker compose logs proxy 2>/dev/null | grep -o 'upstream_key_fingerprint":"[0-9a-f]*' | tail -1 | cut -d'"' -f3 || true)
say "Proxy healthy (upstream key fingerprint ${fp:-?})"

# --- first client --------------------------------------------------------
if [ -n "$CLIENT" ]; then
	args=(add -id "$CLIENT" -concurrency "$CLIENT_CONC")
	[ -n "$CLIENT_MODELS" ] && args+=(-models "$CLIENT_MODELS")
	[ -n "$CLIENT_IPS" ] && args+=(-allow-ips "$CLIENT_IPS")
	TOKEN=$(docker compose run --rm --no-deps -T proxy token "${args[@]}" 2>/dev/null) || die "could not create client $CLIENT"
	say "Client '$CLIENT' created. Its token (shown once; store it securely):"
	printf '%s\n' "$TOKEN"
fi

# --- end-to-end check through HTTPS -----------------------------------------
say "Waiting for HTTPS on https://$DOMAIN (certificate issuance can take ~30s)"
ok=0
for _ in $(seq 30); do
	curl -fsS -m 5 "https://$DOMAIN/healthz" >/dev/null 2>&1 && { ok=1; break; }
	sleep 3
done
if [ "$ok" = 1 ]; then
	say "https://$DOMAIN/healthz is up"
	if [ -n "${TOKEN:-}" ] && [ -z "$CLIENT_IPS" ]; then # an allowlisted token may not work from this host
		n=$(curl -fsS -m 30 -H "Authorization: Bearer $TOKEN" "https://$DOMAIN/v1/models" | grep -o '"id"' | wc -l | tr -d ' ') &&
			say "Upstream reachable: $n models visible to '$CLIENT'" ||
			say "Upstream check failed: GET /v1/models did not succeed (check the key and base URL)"
	fi
else
	say "HTTPS not reachable yet. Check that ports 80/443 are open and DNS points here: docker compose logs caddy"
fi

cat >&2 <<EOF

Done. Gateway: https://$DOMAIN/v1
EOF
if [ -n "$ADMIN_KEY" ]; then
	cat >&2 <<EOF

Admin key (shown once; put it in your password manager):

  $ADMIN_KEY

Manage tokens from your own machine:
  pip install "pxclient @ git+https://github.com/parsewave/shellbench-router.git#subdirectory=clients/python"
  export PX_ADMIN_URL=https://$DOMAIN PX_ADMIN_KEY=<the key above>
  pxadmin add alice --allow-ips <their IP>
EOF
	ADMIN_KEY=""
fi
cat >&2 <<EOF

On this server, scripts/keys.sh does the same (add, list, rotate, revoke, ...).
See README.md for the next steps.
EOF
