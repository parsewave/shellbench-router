#!/usr/bin/env bash
# Local end-to-end smoke test + benchmark against the mock upstream.
#
#   scripts/e2e.sh                 # smoke test, SDK test (if PYTHON has openai), benchmarks
#   PYTHON=/path/to/venv/bin/python scripts/e2e.sh
#   SKIP_BENCH=1 scripts/e2e.sh
set -euo pipefail
cd "$(dirname "$0")/.."

WORK=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$WORK"' EXIT
PYTHON=${PYTHON:-python3}
MOCK_ADDR=127.0.0.1:19999
PROXY_ADDR=127.0.0.1:18080
METRICS_ADDR=127.0.0.1:19090
UPSTREAM_KEY=sk-mock-upstream-key-e2e-0123456789

echo "== build"
go build -o "$WORK/oaiproxy" ./cmd/oaiproxy
go build -o "$WORK/mockupstream" ./tools/mockupstream
go build -o "$WORK/loadgen" ./tools/loadgen

echo "== token CLI"
export TOKENS_FILE="$WORK/tokens.json"
ALICE=$("$WORK/oaiproxy" token add -id alice -note "full access" 2>/dev/null)
BOB=$("$WORK/oaiproxy" token add -id bob -models gpt-4o-mini -rpm 6000 -concurrency 64 -expires 90d 2>/dev/null)
BENCH=$("$WORK/oaiproxy" token add -id bench 2>/dev/null)
OLD=$("$WORK/oaiproxy" token add -id rotating 2>/dev/null)
NEW=$("$WORK/oaiproxy" token rotate -id rotating -grace 1h 2>/dev/null)
"$WORK/oaiproxy" token list
grep -q "$ALICE" "$TOKENS_FILE" && { echo "FAIL: plaintext token in tokens file"; exit 1; }
stat -f '%Lp' "$TOKENS_FILE" 2>/dev/null | grep -q 600 || stat -c '%a' "$TOKENS_FILE" | grep -q 600

echo "== start mock upstream + proxy"
"$WORK/mockupstream" -addr "$MOCK_ADDR" -key "$UPSTREAM_KEY" -chunk-delay 2ms >"$WORK/mock.log" 2>&1 &
MOCK_PID=$!
UPSTREAM_BASE_URL="http://$MOCK_ADDR/v1" ALLOW_INSECURE_UPSTREAM=true UPSTREAM_API_KEY="$UPSTREAM_KEY" \
LISTEN_ADDR="$PROXY_ADDR" METRICS_ADDR="$METRICS_ADDR" ACCESS_LOG_FILE="$WORK/access.jsonl" TOKENS_RELOAD_INTERVAL=200ms \
  "$WORK/oaiproxy" serve >"$WORK/proxy.log" 2>&1 &
PROXY_PID=$!
for _ in $(seq 50); do curl -sf "http://$PROXY_ADDR/healthz" >/dev/null && break; sleep 0.1; done

BASE="http://$PROXY_ADDR/v1"
fail=0
expect() { # name expected_status curl-args...
  local name=$1 want=$2; shift 2
  local got; got=$(curl -s -o "$WORK/body" -w '%{http_code}' "$@")
  if [[ "$got" == "$want" ]]; then echo "PASS  $name ($got)"; else echo "FAIL  $name: got $got want $want: $(head -c 300 "$WORK/body")"; fail=1; fi
}
J=(-H "Content-Type: application/json")
expect "healthz"                         200 "http://$PROXY_ADDR/healthz"
expect "no token -> 401"                 401 "$BASE/models"
expect "bad token -> 401"                401 -H "Authorization: Bearer sk-px-nope" "$BASE/models"
expect "upstream key as token -> 401"    401 -H "Authorization: Bearer $UPSTREAM_KEY" "$BASE/models"
expect "alice chat"                      200 -H "Authorization: Bearer $ALICE" "${J[@]}" -d '{"model":"o3","messages":[{"role":"user","content":"hi"}]}' "$BASE/chat/completions"
expect "bob allowed model"               200 -H "Authorization: Bearer $BOB" "${J[@]}" -d '{"model":"gpt-4o-mini","messages":[]}' "$BASE/chat/completions"
expect "bob disallowed model -> 403"     403 -H "Authorization: Bearer $BOB" "${J[@]}" -d '{"model":"gpt-4o","messages":[]}' "$BASE/chat/completions"
expect "unconfigured endpoint -> 404"    404 -H "Authorization: Bearer $ALICE" "$BASE/files"
expect "rotated: old token in grace"     200 -H "Authorization: Bearer $OLD" "$BASE/models"
expect "rotated: new token"              200 -H "Authorization: Bearer $NEW" "$BASE/models"

echo "-- SSE through proxy (first lines)"
curl -sN -H "Authorization: Bearer $ALICE" "${J[@]}" \
  -d '{"model":"gpt-4o","stream":true,"stream_options":{"include_usage":true},"messages":[]}' "$BASE/chat/completions" | head -3 || true
curl -sN -H "Authorization: Bearer $ALICE" "${J[@]}" -d '{"model":"gpt-4o","stream":true,"messages":[]}' "$BASE/chat/completions" | grep -q '^data: \[DONE\]$' \
  && echo "PASS  SSE ends with [DONE]" || { echo "FAIL  SSE"; fail=1; }

echo "-- hot revoke via CLI"
"$WORK/oaiproxy" token revoke -id bob 2>/dev/null
sleep 0.5
expect "bob after revoke -> 401"         401 -H "Authorization: Bearer $BOB" "$BASE/models"
"$WORK/oaiproxy" token enable -id bob 2>/dev/null
sleep 0.5
expect "bob after enable"                200 -H "Authorization: Bearer $BOB" "$BASE/models"

echo "-- upstream key misconfigured (simulated by wrong key on mock) is not leaked"
"$WORK/mockupstream" -addr 127.0.0.1:19998 -key "some-other-key" >/dev/null 2>&1 &
UPSTREAM_BASE_URL="http://127.0.0.1:19998/v1" ALLOW_INSECURE_UPSTREAM=true UPSTREAM_API_KEY="$UPSTREAM_KEY" \
LISTEN_ADDR=127.0.0.1:18081 "$WORK/oaiproxy" serve >"$WORK/proxy2.log" 2>&1 &
for _ in $(seq 50); do curl -sf "http://127.0.0.1:18081/healthz" >/dev/null && break; sleep 0.1; done
expect "upstream 401 -> 502"             502 -H "Authorization: Bearer $ALICE" "http://127.0.0.1:18081/v1/models"
if grep -q "${UPSTREAM_KEY: -4}" "$WORK/body"; then echo "FAIL  masked upstream key leaked"; fail=1; else echo "PASS  upstream error sanitized: $(cat "$WORK/body")"; fi

if "$PYTHON" -c "import openai" 2>/dev/null; then
  echo "== OpenAI Python SDK"
  PROXY_BASE_URL="$BASE" PROXY_TOKEN="$ALICE" PROXY_TOKEN_RESTRICTED="$BOB" "$PYTHON" tests/sdk/test_openai_sdk.py || fail=1
else
  echo "== skipping SDK test (no 'openai' module for $PYTHON)"
fi

echo "== secret scan of logs"
for s in "$UPSTREAM_KEY" "$ALICE" "$BOB" "$BENCH" "$OLD" "$NEW" "Bearer "; do
  if grep -qF -- "$s" "$WORK/proxy.log" "$WORK/access.jsonl" "$WORK/proxy2.log"; then echo "FAIL  logs contain a secret"; fail=1; fi
done
echo "PASS  no tokens/keys in logs ($(wc -l <"$WORK/access.jsonl" | tr -d ' ') access records)"
echo "sample access record: $(grep '"total_tokens"' "$WORK/access.jsonl" | tail -1)"

if [[ -z "${SKIP_BENCH:-}" ]]; then
  echo "== benchmarks (mock upstream with no added latency => measures pure proxy overhead)"
  kill $MOCK_PID; wait $MOCK_PID 2>/dev/null || true
  "$WORK/mockupstream" -addr "$MOCK_ADDR" -key "$UPSTREAM_KEY" >/dev/null 2>&1 &
  MOCK_PID=$!
  sleep 0.3
  for c in 50 200 500; do
    "$WORK/loadgen" -url "http://$MOCK_ADDR/v1" -token "$UPSTREAM_KEY" -c $c -d 8s -label direct
    "$WORK/loadgen" -url "$BASE" -token "$BENCH" -c $c -d 8s -label via-proxy
    echo "   proxy RSS: $(( $(ps -o rss= -p $PROXY_PID) / 1024 )) MiB"
  done
  for c in 50 200; do
    "$WORK/loadgen" -url "http://$MOCK_ADDR/v1" -token "$UPSTREAM_KEY" -c $c -d 8s -stream -label direct-sse
    "$WORK/loadgen" -url "$BASE" -token "$BENCH" -c $c -d 8s -stream -label via-proxy-sse
  done
  echo "-- realistic: upstream adds 200ms latency, 1000 concurrent clients"
  kill $MOCK_PID; wait $MOCK_PID 2>/dev/null || true
  "$WORK/mockupstream" -addr "$MOCK_ADDR" -key "$UPSTREAM_KEY" -latency 200ms >/dev/null 2>&1 &
  MOCK_PID=$!
  sleep 0.3
  "$WORK/loadgen" -url "http://$MOCK_ADDR/v1" -token "$UPSTREAM_KEY" -c 1000 -d 8s -label direct-200ms
  "$WORK/loadgen" -url "$BASE" -token "$BENCH" -c 1000 -d 8s -label via-proxy-200ms
  echo "   proxy RSS after load: $(( $(ps -o rss= -p $PROXY_PID) / 1024 )) MiB"
  echo "   retried requests: $(grep -c '"retries":[1-9]' "$WORK/access.jsonl" || true) $(grep '"retries":[1-9]' "$WORK/access.jsonl" | head -3)"
  curl -s "http://$METRICS_ADDR/metrics" | grep -E '^(go_goroutines|go_memstats_heap_inuse_bytes|oaiproxy_upstream_retries_total|oaiproxy_inflight)'
fi

[[ $fail == 0 ]] && echo "== ALL E2E CHECKS PASSED" || { echo "== E2E FAILURES"; exit 1; }
