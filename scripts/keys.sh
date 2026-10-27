#!/usr/bin/env bash
# Manage client tokens and the upstream key of a running deployment.
#
#   scripts/keys.sh add -id alice -allow-ips 203.0.113.7 -models gpt-4o-mini -concurrency 16 -expires 90d
#   scripts/keys.sh list
#   scripts/keys.sh set -id alice -concurrency 64
#   scripts/keys.sh rotate -id alice -grace 24h
#   scripts/keys.sh revoke -id alice        # immediate; undo with: enable -id alice
#   scripts/keys.sh remove -id alice
#   scripts/keys.sh upstream-key            # replace the provider's upstream key
#   scripts/keys.sh admin-key               # enable the admin HTTP API / rotate its key
#   scripts/keys.sh check TOKEN [MODEL]     # verify a client token end-to-end
#
# Client tokens are printed once on stdout (everything else on stderr), so
# TOKEN=$(scripts/keys.sh add -id alice ...) captures only the secret.
set -euo pipefail
cd "$(dirname "$0")/.."

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
[ -f .env ] || die "no .env here; run scripts/setup.sh first"
compose() { docker compose "$@"; }

case ${1:-help} in
add | list | rotate | revoke | enable | set | remove)
	compose run --rm --no-deps -T proxy token "$@"
	;;

upstream-key)
	# Overwrite in place: the key file is bind-mounted by inode, so a
	# rename-style replace would not reach the running container.
	[ -e secrets/upstream_api_key ] || die "secrets/upstream_api_key not found (is UPSTREAM_API_KEY_FILE in use?)"
	if [ -t 0 ]; then
		read -r -s -p "New upstream API key (input hidden): " KEY
		echo >&2
	else
		IFS= read -r KEY || true
	fi
	KEY=$(printf '%s' "$KEY" | tr -d '[:space:]')
	[ -n "$KEY" ] || die "empty key"
	SUDO=""
	[ -w secrets/upstream_api_key ] || SUDO=sudo
	since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
	printf '%s' "$KEY" | $SUDO tee secrets/upstream_api_key >/dev/null
	KEY=""
	for _ in $(seq 10); do
		sleep 1
		fp=$(compose logs --since "$since" proxy 2>/dev/null | grep 'upstream key reloaded' | grep -o 'fingerprint":"[0-9a-f]*' | tail -1 | cut -d'"' -f3 || true)
		[ -n "$fp" ] && break
	done
	if [ -z "${fp:-}" ]; then
		echo "Key file updated but no hot reload seen; restarting the proxy." >&2
		compose restart proxy >/dev/null
		sleep 3
		fp=$(compose logs --since "$since" proxy 2>/dev/null | grep -o 'upstream_key_fingerprint":"[0-9a-f]*' | tail -1 | cut -d'"' -f3 || true)
	fi
	echo "Upstream key active (fingerprint ${fp:-unknown}). Revoke the old key at the provider." >&2
	;;

admin-key)
	# Generates the admin API key, prints it once, and enables the API. The
	# file is overwritten in place (bind-mounted by inode), so rerunning this
	# rotates the key without a restart.
	install -d -m 700 secrets
	KEY="sk-pxadmin-$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n')"
	SUDO=""
	[ "$(id -u)" = 0 ] || { sudo -n true 2>/dev/null && SUDO=sudo; } || true
	fresh=0
	if [ -e secrets/admin_api_key ]; then
		if [ -w secrets/admin_api_key ]; then
			printf '%s' "$KEY" >secrets/admin_api_key
		elif [ -O secrets/admin_api_key ]; then # our own 0444 file (no-sudo setup)
			chmod u+w secrets/admin_api_key && printf '%s' "$KEY" >secrets/admin_api_key && chmod 0444 secrets/admin_api_key
		else
			printf '%s' "$KEY" | $SUDO tee secrets/admin_api_key >/dev/null
		fi
	else
		fresh=1
		(umask 077 && printf '%s' "$KEY" >secrets/admin_api_key)
		if [ "$(uname -s)" = Linux ] && { [ -n "$SUDO" ] || [ "$(id -u)" = 0 ]; }; then
			$SUDO chown 65532:65532 secrets/admin_api_key
			$SUDO chmod 0400 secrets/admin_api_key
		else
			chmod 0444 secrets/admin_api_key
		fi
	fi
	if ! grep -qE '^COMPOSE_FILE=.*deploy/docker-compose.admin.yml' .env; then
		if grep -qE '^COMPOSE_FILE=' .env; then
			sed -i.bak -E 's#^(COMPOSE_FILE=.*)$#\1:deploy/docker-compose.admin.yml#' .env && rm -f .env.bak
		else
			echo 'COMPOSE_FILE=docker-compose.yml:deploy/docker-compose.admin.yml' >>.env
		fi
		fresh=1
	fi
	if [ "$fresh" = 1 ]; then
		echo "Enabling the admin API (recreating the proxy)..." >&2
		compose up -d proxy >&2
	else
		echo "Admin key rotated; the proxy picks it up within seconds." >&2
	fi
	DOMAIN=$(grep -E '^PROXY_DOMAIN=' .env | cut -d= -f2-)
	echo "Admin API: https://$DOMAIN/admin/clients  (Authorization: Bearer <key>)" >&2
	echo "The admin key is printed below exactly once; store it in a password manager." >&2
	printf '%s\n' "$KEY"
	KEY=""
	;;

check)
	TOKEN=${2:-}
	MODEL=${3:-}
	[ -n "$TOKEN" ] || die "usage: scripts/keys.sh check TOKEN [MODEL]"
	DOMAIN=$(grep -E '^PROXY_DOMAIN=' .env | cut -d= -f2-)
	BASE="https://$DOMAIN/v1"
	code=$(curl -s -o /tmp/keys-check.$$ -w '%{http_code}' -m 30 -H "Authorization: Bearer $TOKEN" "$BASE/models")
	echo "GET $BASE/models -> $code ($(grep -o '"id"' /tmp/keys-check.$$ | wc -l | tr -d ' ') models)" >&2
	if [ -n "$MODEL" ] && [ "$code" = 200 ]; then
		code=$(curl -s -o /tmp/keys-check.$$ -w '%{http_code}' -m 120 -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
			-d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Reply with OK\"}]}" "$BASE/chat/completions")
		echo "POST $BASE/chat/completions ($MODEL) -> $code: $(head -c 300 /tmp/keys-check.$$)" >&2
	fi
	rm -f /tmp/keys-check.$$
	[ "$code" = 200 ]
	;;

help | -h | --help)
	sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
	;;

*)
	die "unknown command '$1' (try: scripts/keys.sh help)"
	;;
esac
