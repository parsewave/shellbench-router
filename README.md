# shellbench_proxy: authenticated OpenAI-compatible API gateway

A small Go reverse proxy that lets a model provider share access to their API account **without sharing their API key**. The provider hosts the gateway with their real key (OpenAI, OpenRouter, PackyAPI, or any OpenAI-compatible API). Each consumer gets their own proxy token, which can be revoked, rotated, expired, and limited independently. Clients keep using the standard OpenAI SDKs; only `base_url` and `api_key` change.

```
client (OpenAI SDK)                 provider's server                                  upstream
 base_url=https://host/v1  ──TLS──▶ Caddy :443 ──HTTP──▶ proxy :8080 ──TLS──▶ api.openai.com/v1
 api_key=sk-px-… (proxy token)      (HTTPS, ACME)        │ 1 verify proxy token (SHA-256, constant time)   openrouter.ai/api/v1
                                                         │ 2 route allow-list (else 404)                    any OpenAI-compatible API
                                                         │ 3 per-token rate / concurrency limits (429)
                                                         │ 4 per-token model allow-list from JSON body (403)
                                                         │ 5 drop client credentials, inject provider key
                                                         │ 6 stream the response back unmodified (SSE flushed per event)
                                                         └ structured logs: metadata + token usage only
```

* Go standard library only, with no third-party modules. About 2,750 lines for the proxy itself. The distroless image is about 25 MB.
* `httputil.ReverseProxy` with a tuned transport: HTTP/2, connection pooling, no gzip re-encoding.
* Request bodies are bounded and inspected only for the top-level `model`/`stream` fields. Everything else is forwarded byte-for-byte.
* Responses are never buffered, and streaming stays streaming.

Contents: [Quick start](#1-quick-start) · [Providers](#2-providers) · [Managing keys](#3-managing-keys) · [Clients](#4-using-the-gateway-clients) · [Configuration](#5-configuration) · [Reliability](#6-reliability-behaviour) · [Logging](#7-logging-and-metrics) · [Security](#8-security-model) · [Results](#9-test-and-benchmark-results) · [Testing](#10-running-the-tests) · [Limitations](#11-limitations) · [Layout](#12-repository-layout)

---

## 1. Quick start

Prerequisites: a Linux host with Docker and Docker Compose v2, and ports 80/443 reachable from the internet (for Let's Encrypt). A DNS name is optional, since `--domain auto` uses `<public-ip>.sslip.io`.

```bash
git clone https://github.com/Parsewave-internal/shellbench_proxy.git && cd shellbench_proxy

# Interactive: asks for provider, hostname and the upstream key (input hidden)
scripts/setup.sh

# Or fully specified, e.g. OpenRouter with a first client:
scripts/setup.sh --provider openrouter --domain auto \
  --referer https://github.com/your-org/your-app --title "My Benchmark" \
  --client alice --client-models 'openai/*,anthropic/*' --client-concurrency 64
```

`setup.sh` does the following:
1. Stores the upstream key in `secrets/upstream_api_key`, never in `.env`. The file is owner-only, owned by the container's uid 65532 (mode 0400).
2. Writes `.env` with the provider's base URL and `COMPOSE_FILE`, so plain `docker compose …` picks up the key-file override.
3. Runs `docker compose up -d --build` and waits for the proxy to report healthy.
4. Optionally creates the first client token and prints it **once**.
5. Checks `https://<host>/healthz` and `GET /v1/models` end to end.

Non-interactive (CI or automation): `UPSTREAM_KEY=… scripts/setup.sh --provider openai --domain llm.example.com --yes`.

Options: `--provider openai|openrouter|packy|custom`, `--base-url URL` (custom), `--domain NAME|auto`, `--host-network`, `--referer`/`--title` (OpenRouter attribution), `--client ID`, `--client-models LIST`, `--client-concurrency N`, `--force`, `--yes`.

**Host networking.** `--host-network` adds `deploy/docker-compose.host.yml`. Caddy and the proxy then use the host network, with the proxy bound to `127.0.0.1:8080`. Use it on hosts where Docker can't create more networks ("all predefined address pools have been fully subnetted"), or to skip the docker-proxy hop under heavy load.

**Manual setup**, without the script: copy `.env.example` to `.env` (chmod 600), put the key in `secrets/upstream_api_key` (see `deploy/docker-compose.keyfile.yml`), then run `docker compose up -d --build`.

## 2. Providers

Any OpenAI-compatible upstream works; set `UPSTREAM_BASE_URL` (or use `--provider`).

| Provider | `UPSTREAM_BASE_URL` | Notes |
|---|---|---|
| OpenAI | `https://api.openai.com/v1` | Optional `UPSTREAM_ORGANIZATION`, `UPSTREAM_PROJECT`. |
| OpenRouter | `https://openrouter.ai/api/v1` | See below. |
| PackyAPI | `https://www.packyapi.com/v1` | See below. |
| Other | `https://<host>/v1` | Must be https. Use `ALLOW_INSECURE_UPSTREAM=true` only for local mocks. |

**OpenRouter.**
* Model ids contain a slash (`openai/gpt-4.1-nano`, `anthropic/claude-…`). Allow-lists work with prefixes: `-models 'openai/*,mistralai/mistral-nemo'`.
* `GET /v1/models/{id}` can't be routed for slash ids. Use `GET /v1/models`, which is filtered per token.
* App attribution: `UPSTREAM_HEADERS=HTTP-Referer=https://your.site;X-Title=Your App` (or `--referer`/`--title`). Client-sent attribution headers are dropped by the header allow-list, so set them on the provider side.
* Chat Completions, Responses, embeddings and model listing all work through the gateway. See [Results](#9-test-and-benchmark-results).
* Check spend with `GET https://openrouter.ai/api/v1/key` using the upstream key.

**PackyAPI** (new-api based relay). Behaviour observed in October 2026 that clients need to know about:
* **Available models depend on the key's group.** Check with `GET /v1/models` through the gateway. On the `codex-sale` group, GPT models accept **only the Responses API**; `/v1/chat/completions` returns `protocol_not_supported`. Gemini models accept chat completions.
* **Send list-form `input`** (`[{"role":"user","content":"…"}]`). About 10% of requests with string `input` land on a channel that answers `400 Input must be a list`.
* **Non-streaming Responses return an empty `output`**, though usage is still billed, and the final `response.completed` event is empty too. Read the text from the `response.output_text.delta` events (the Codex CLI does this).
* The codex channel adds about 4.4k cached instruction tokens to every request.
* **Channels can disappear temporarily** (`model_not_found: 当前令牌未覆盖供应商`) and come back on their own.
* Check spend with `GET https://www.packyapi.com/v1/dashboard/billing/usage` using the upstream key. `total_usage` is in cents.

## 3. Managing keys

There are two kinds of keys: **client tokens**, which you hand out, and the **upstream key**, which is the provider's own and never leaves the server.

### Client tokens: `scripts/keys.sh`

```bash
scripts/keys.sh add -id alice -models gpt-4o-mini,o3* -rpm 600 -concurrency 32 -expires 90d   # prints token once
scripts/keys.sh add -id bob -concurrency 64                       # all models
scripts/keys.sh list                                              # status, limits, expiry, hints; never full tokens
scripts/keys.sh set    -id alice -models 'openai/*' -rpm 1200 -expires never
scripts/keys.sh rotate -id alice -grace 24h                       # new token; old one valid 24h more (default 0 = revoked now)
scripts/keys.sh revoke -id alice                                  # immediate; undo with: enable -id alice
scripts/keys.sh remove -id alice                                  # delete entirely
scripts/keys.sh check  sk-px-… [model]                            # verify a token end-to-end through HTTPS

TOKEN=$(scripts/keys.sh add -id carol)    # only the token goes to stdout
```

* `keys.sh` wraps `docker compose run --rm --no-deps proxy token …`. Without Docker, the same commands are `oaiproxy token …`, run against `TOKENS_FILE`.
* **Format and storage.** Tokens are `sk-px-` plus 256 random bits. Only `sha256(token)` and a 4-character hint are stored, in `/config/tokens.json` on the `proxy_config` volume. The file is written atomically with mode 0600. See `deploy/tokens.example.json` for the format.
* **Changes apply within about 2 seconds** without a restart. `kill -HUP` forces an immediate reload. An invalid file is rejected and the previous one stays active. A missing file fails closed: every request gets 401.
* **Model patterns** are exact and case-sensitive. A trailing `*` matches by prefix. An empty list or `*` allows every model. Restricted tokens see only their allowed models in `GET /v1/models`.
* **Limits.** `rpm` is a token bucket (`burst` defaults to `rpm`), and `concurrency` caps in-flight requests per token. When a limit is hit, the proxy returns 429 with `Retry-After` immediately rather than queuing; SDK retries handle it. New tokens are unlimited by default, so **give every client a `-concurrency` limit** so one client can't use all of `MAX_INFLIGHT`.
* Revoking a token doesn't cut streams already in flight; they end normally or at `UPSTREAM_TIMEOUT`.

### Admin API (HTTP)

The same operations are available over HTTPS, so tokens can be managed without SSH. Enable it once on the server:

```bash
scripts/keys.sh admin-key      # prints the admin key once; rerun to rotate it (no restart)
```

This writes `secrets/admin_api_key` (owner-only, like the upstream key), adds `deploy/docker-compose.admin.yml` to `COMPOSE_FILE`, and recreates the proxy. Without an admin key, `/admin/` answers 404.

```bash
A="Authorization: Bearer $ADMIN_KEY"; B=https://llm.example.com

curl -H "$A" $B/admin/clients                                                     # list (never shows tokens)
curl -H "$A" $B/admin/clients -d '{"id":"alice","models":["gpt-4o-mini","o3*"],"rpm":600,"max_concurrent":32,"expires":"90d"}'
                                                                                  # -> 201 {"client":{...},"token":"sk-px-..."} (token shown once)
curl -H "$A" $B/admin/clients/alice
curl -H "$A" -X PATCH $B/admin/clients/alice -d '{"rpm":1200,"models":["*"]}'      # only the given fields change
curl -H "$A" -X POST  $B/admin/clients/alice/rotate -d '{"grace":"24h"}'          # -> new token; old one valid 24h
curl -H "$A" -X POST  $B/admin/clients/alice/revoke                               # or /enable
curl -H "$A" -X DELETE $B/admin/clients/alice
curl -H "$A" $B/admin/clients/alice/keys -d '{"public_key":"ed25519:...","note":"ci box"}'   # require signing
curl -H "$A" -X DELETE $B/admin/clients/alice/keys/k_0123456789ab                 # 409 if it is the last key, unless ?allow_unsigned=true
```

* Fields: `models` (`[]` or `["*"]` = all), `rpm`, `burst`, `max_concurrent`, `expires` (`90d`, `12h`, `2027-01-31`, RFC3339, `never`), `note`, and on create optionally `public_keys: [{"public_key","note","expires"}]`. Unknown fields are rejected.
* Changes apply immediately. The API and the CLI edit `tokens.json` under a shared file lock, so concurrent changes from either are never lost.
* Every change is logged (`"msg":"admin change"`, action, client, remote address); tokens and the admin key never are.
* The admin key is all-powerful: keep it in a password manager, not in scripts or chat. Rotate it with `scripts/keys.sh admin-key`.

### Request signing (leak-resistant tokens)

A bearer token works for anyone who has a copy. For clients that register an **Ed25519 public key**, the proxy additionally requires every request to be **signed with the matching private key**, so a leaked token (from logs, a repo, a chat message) is useless on its own, and a leaked private key is useless without the token.

1. The client creates a key pair on its own machine; the private key never leaves it:
   ```bash
   pip install ./clients/python          # or: openssl genpkey -algorithm ed25519 -out private.pem
   pxkey generate                        # writes ~/.pxkey/private.pem (0600), prints ed25519:...
   ```
2. They send you the printed **public** key (it is not secret) and you register it:
   `scripts/keys.sh add-key -id alice -pubkey ed25519:...` or `POST /admin/clients/alice/keys`. From then on, alice's unsigned requests get `401 signature_required`.
3. They use the signing client; everything else is the stock OpenAI SDK:
   ```python
   from pxclient import signed_openai          # signed_async_openai for AsyncOpenAI
   client = signed_openai(base_url="https://llm.example.com/v1", api_key="sk-px-…", key_file="~/.pxkey/private.pem")
   client.responses.create(model="gpt-4o-mini", input="hi")
   ```

What is signed (`internal/signing`): `PX-ED25519-V1`, method, host, path and query, timestamp, a per-request nonce, and the SHA-256 of the body, sent as `X-Px-Timestamp`, `X-Px-Nonce`, `X-Px-Signature`. The proxy accepts timestamps within `SIGNATURE_MAX_SKEW` (default 2m) and rejects reused nonces, so a captured request can't be altered or replayed. Errors: `signature_required`, `malformed_signature`, `signature_expired` (check the client clock), `invalid_signature`, `signature_replayed`. Keys can have an expiry; a client may hold up to 8, so rotate by adding the new key before removing the old one. Tools that only accept a base URL and API key (no custom HTTP client) can't sign; keep those clients unsigned.

### Upstream key: `scripts/keys.sh upstream-key`

```bash
scripts/keys.sh upstream-key              # prompts (hidden); or: printf %s "$NEW_KEY" | scripts/keys.sh upstream-key
```

The command overwrites `secrets/upstream_api_key` **in place**, waits for the proxy's `upstream key reloaded` log line, and prints the new non-reversible fingerprint. If no hot reload happens, it restarts the proxy. Then revoke the old key at the provider.

Why in place: Docker bind-mounts a single file by inode. Editors and `mv` replace the inode, which the running container never sees (we tested this), so the rotation would silently not happen until a restart. If you rotate by hand, use `sudo tee secrets/upstream_api_key` or restart the proxy afterwards. The startup log line `upstream_key_fingerprint` always shows which key is active.

## 4. Using the gateway (clients)

```python
from openai import OpenAI
client = OpenAI(base_url="https://llm.example.com/v1", api_key="sk-px-…your proxy token…")

client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": "hi"}])
for ev in client.chat.completions.create(model="gpt-4o-mini", messages=[...], stream=True): ...
client.responses.create(model="o3", input=[{"role": "user", "content": "…"}], reasoning={"effort": "high"})
client.embeddings.create(model="text-embedding-3-small", input=["a", "b"])
```

```bash
export OPENAI_BASE_URL=https://llm.example.com/v1 OPENAI_API_KEY=sk-px-…   # honored by most tools and SDKs
```

Errors use OpenAI's error format, so SDK exception types work as usual:

| Status | `code` | Meaning |
|---|---|---|
| 401 | `invalid_api_key` | Proxy token missing, unknown, revoked, or expired |
| 403 | `model_not_allowed` | Token is not permitted to use that model, or a restricted token sent a non-JSON body |
| 400 | `model_required` / `invalid_json` / `invalid_content_type` | Restricted token sent no `model`, or the body or headers are malformed or ambiguous |
| 404 | `unknown_url` / `model_not_found` | Endpoint not enabled on this gateway / model hidden from this token |
| 413 | `request_too_large` | Body exceeds `MAX_REQUEST_BYTES` |
| 429 | `rate_limit_exceeded` / `concurrency_limit_exceeded` | Per-token limit (with `Retry-After`) |
| 429 | (upstream's code) | Upstream rate limit, after the gateway's own safe retries |
| 502 | `upstream_auth_error` | The provider's upstream key was rejected. Contact the operator. |
| 502 / 504 | `upstream_unavailable` / `upstream_timeout` | Upstream unreachable / too slow |
| 503 | `proxy_overloaded` | `MAX_INFLIGHT` or `MAX_BUFFERED_BYTES` reached |

Each response carries `X-Proxy-Request-Id`, which matches the gateway logs, plus the upstream's own request id when it sends one.

## 5. Configuration

All configuration is through environment variables (`.env`). See `.env.example`.

| Variable | Default | Notes |
|---|---|---|
| `UPSTREAM_BASE_URL` | `https://api.openai.com/v1` | Any OpenAI-compatible base URL; must be https |
| `UPSTREAM_API_KEY_FILE` / `UPSTREAM_API_KEY` | — | Exactly one is required. Prefer the file; it is hot-reloaded when overwritten in place. |
| `UPSTREAM_HEADERS` | — | Extra upstream headers, `Name=value;Name2=value2`. Credential headers are rejected. |
| `UPSTREAM_ORGANIZATION`, `UPSTREAM_PROJECT` | — | OpenAI only. Client-supplied values are always dropped. |
| `PROXY_DOMAIN` | — | Hostname Caddy serves and gets a certificate for |
| `COMPOSE_FILE` | — | Compose overrides to apply (set by `setup.sh`) |
| `TOKENS_FILE` | `/config/tokens.json` in Docker | |
| `ALLOWED_ROUTES` | see below | Comma-separated `METHOD /v1/path`; `*` matches one path segment. Replaces the defaults. |
| `LISTEN_ADDR` | `:8080` (`127.0.0.1:8080` with host networking) | |
| `METRICS_ADDR` | off | Prometheus `/metrics` on a separate listener. Unauthenticated, so keep it on loopback or a trusted network. |
| `MAX_REQUEST_BYTES` | 32 MiB | Per request body. Caddy also caps at 64 MB. |
| `MAX_BUFFERED_BYTES` | 1 GiB | Global cap on request bodies held in memory (503 beyond) |
| `MAX_INFLIGHT` | 2048 | Global concurrency cap (503 beyond) |
| `MAX_RETRIES` | 2 | 0–3. See §6. |
| `MAX_RETRY_WAIT` | 20s | A longer upstream `Retry-After` is passed to the client instead |
| `UPSTREAM_TIMEOUT` | 30m | Total per request (long reasoning) |
| `STREAM_IDLE_TIMEOUT` | 10m | Max silence between upstream bytes. Also frees clients that stop reading. |
| `BODY_READ_TIMEOUT` | 60s | Slow-upload guard |
| `LOG_FORMAT` / `LOG_LEVEL` | `json` / `info` | stdout |
| `ACCESS_LOG_FILE` | — | Optional JSONL access log. Put it on its own rotated volume. |
| `SHUTDOWN_TIMEOUT` | 30s | Grace period for in-flight requests on SIGTERM |
| `ADMIN_API_KEY_FILE` / `ADMIN_API_KEY` | — | Enables the admin API at `/admin/` (set up by `scripts/keys.sh admin-key`). File form is hot-reloaded. |
| `SIGNATURE_MAX_SKEW` | 2m | Accepted clock difference for signed requests (10s–1h) |

Default routes: `GET /v1/models`, `GET /v1/models/*`, `POST /v1/chat/completions`, `POST /v1/responses`, `POST /v1/responses/input_tokens`, `GET|DELETE /v1/responses/*`, `POST /v1/responses/*/cancel`, `GET /v1/responses/*/input_items`, `POST /v1/embeddings`. Any other path returns 404 without contacting the upstream. Clients always call `/v1/...`; the gateway maps that onto the upstream base path (e.g. OpenRouter's `/api/v1`).

## 6. Reliability behaviour

**Retries never duplicate potentially billable work:**

| Condition | Retried? | Why |
|---|---|---|
| Dial / DNS failure | yes, any method | The request never left the gateway |
| HTTP 429 (not `insufficient_quota`) | yes, any method | The upstream rejected it without processing it |
| 5xx or dropped connection on GET/DELETE | yes | Idempotent |
| 5xx, timeout, or dropped connection on **POST** | **no** | It may already have been processed and billed |
| After any response byte reached the client | **never** | Retries happen before the response is handed to the client |

* Backoff is exponential with jitter (500 ms base, 8 s cap). The gateway honors `Retry-After` and `retry-after-ms` up to `MAX_RETRY_WAIT`.
* `Idempotency-Key` isn't forwarded, so Go's transport never replays a POST on its own.
* OpenAI SDKs also retry 429/5xx themselves (`max_retries=2`). Set `MAX_RETRIES=0` if you want only client-side retries.
* **Streaming:** SSE is flushed to the client on every upstream write. If the upstream dies mid-stream, the client connection is aborted rather than cleanly closed, so the SDK raises an error instead of returning a silently truncated answer.
* **Cancellation:** a client disconnect cancels the upstream request at once, both mid-stream and while waiting for headers. The provider doesn't pay for abandoned generations.
* **Upstream errors:** an upstream 401 becomes a generic 502 `upstream_auth_error`; the upstream message, which may quote part of the key, is never relayed. Upstream 403s become a generic 403. Other upstream errors are passed through, so SDK users see real validation messages, but anything that looks like a key or an `org-`/`proj_`/`user-` id is masked first. A JSON error mislabelled as `text/event-stream` is relabelled `application/json`.

## 7. Logging and metrics

One structured record per request goes to stdout, and optionally to a JSONL file:

```json
{"time":"…","level":"INFO","msg":"request","request_id":"px_162a…","client":"alice","method":"POST",
 "endpoint":"POST /v1/responses","path":"/v1/responses","model":"gpt-6.1-terra","stream":true,"status":200,
 "upstream_status":200,"latency_ms":2412.4,"ttfb_ms":2063.2,"retries":0,"input_tokens":4388,"output_tokens":5,
 "reasoning_tokens":0,"cached_tokens":4224,"total_tokens":4393}
```

* **Token usage** comes from the response's final `usage` object. That works for regular JSON, the Chat Completions stream's last chunk (clients must send `stream_options.include_usage`; the gateway never edits requests to add it), and the Responses API's `response.completed` event. It's parsed from the last 16 KiB only, so responses are never buffered.
* **Never logged:** prompts, completions, headers, and tokens.
* `error` holds a reason code: `invalid_token`, `revoked_token`, `model_not_allowed`, `client_disconnected`, `upstream_idle_timeout`, `upstream_stream_interrupted`, …
* Unauthenticated requests are logged at most 20 per second.
* `/healthz` is public.
* **Metrics:** `/metrics` lives on `METRICS_ADDR`, which Caddy doesn't expose. It reports `oaiproxy_requests_total{client,endpoint,code}`, `oaiproxy_errors_total{reason}`, `oaiproxy_tokens_total{client,model,kind}`, latency and TTFB histograms, retries, in-flight requests, goroutines, and heap.

## 8. Security model

* **The upstream key stays on the server.** It lives only in the proxy container, as a mounted file or env var. It isn't in the image (`.dockerignore` excludes `.env`, `secrets/`, `config/`), isn't in Caddy, and isn't in logs, which show only a 4-byte SHA-256 fingerprint. It never appears in responses: `OpenAI-Organization`, `OpenAI-Project`, `Set-Cookie` and `x-ratelimit-*` headers are stripped (the last reveal the provider's tier and the combined usage of all clients), and error bodies and `/v1/models` are scrubbed.
* **Client credentials never go upstream.** Request headers are forwarded by allow-list only: `Content-Type`, `Accept`, `User-Agent`, `OpenAI-Beta`, `X-Client-Request-Id`, `X-Stainless-*`. `Authorization`, cookies, `X-Forwarded-*`, client org/project headers and request trailers are dropped, so client IPs are not sent upstream. Query strings are forwarded only on GET/DELETE.
* **Authentication** hashes the presented token and compares it against every stored hash with `crypto/subtle`, with no early exit. Every failure kind returns the same 401. There's no admin API; management happens through the CLI on the host.
* **Model enforcement** uses an exact-key JSON scanner instead of `encoding/json` struct decoding, which matches keys case-insensitively. That closes parser-differential bypasses such as `{"model":"o3","MODEL":"gpt-4o"}`. Duplicate `model` keys, escaped keys, invalid JSON, and multiple or malformed `Content-Type` headers are all handled. Restricted tokens may only send JSON, and upstream always receives exactly `Content-Type: application/json` for them. The scanner is fuzz-tested against a reference decoder.
* **Not an open proxy.** The upstream host is fixed by configuration. Only allow-listed method+path pairs are forwarded. Percent-encoded slashes, empty segments and dot segments are rejected, not normalized.
* **Resource limits.** Bodies are bounded per request and globally, with the budget reserved before reading, so stalled uploads cannot exhaust memory. A client that stops reading a stream is disconnected at `STREAM_IDLE_TIMEOUT`, which frees its slot.
* **Container hardening:** distroless static image, uid 65532, read-only rootfs, `cap_drop: ALL`, `no-new-privileges`. Only Caddy publishes ports.

## 9. Test and benchmark results

### Automated tests
* **Go suite:** 38 tests plus an 11-case retry table. Passes with `go test -race`, repeated runs.
  * **Core properties:** valid and invalid tokens; per-client model access, including parser-differential and Content-Type bypass attempts; that provider keys never reach clients and client credentials never reach the upstream; byte-for-byte passthrough; incremental SSE; 300 concurrent requests; per-token and global limits.
  * **Failure handling:** cancellation propagated mid-stream and before headers; upstream and idle timeouts; a stalled reader being released; the retry policy; dropped connections and interrupted streams not replayed; and logs, access log and metrics free of secrets.
* **Fuzzing:** about 3.5M executions of the model-field scanner against a reference decoder, with no disagreement.
* **OpenAI Python SDK compatibility through the gateway:**
  * against a mock upstream: 11/11 (openai-python 2.48);
  * **against real OpenRouter: 11/11** (chat non-stream/stream/tools, Responses non-stream/stream, embeddings, model list, filtered model list, 401, 403, 20 concurrent async streams);
  * **against real PackyAPI: 9/9** (openai-python 3.39; embeddings and non-streaming Responses skipped because of the PackyAPI limitations in §2).
* **Independent security review:** found no credential exposure, auth bypass or open-proxy path. Its availability and hardening findings were fixed, each with a regression test: memory reservation for declared body sizes, stalled readers pinning slots, Content-Type tricks, trailer forwarding, rate-limit header exposure, and log flooding.

### Gateway capacity (mock LLM upstream)

This isolates the gateway's own cost. The setup:
* **Gateway:** Caddy and the proxy on a 16-vCPU / 30 GB Linux VM that was also running other workloads. HTTPS with a Let's Encrypt certificate, HTTP/2 from clients.
* **Load:** generated from a separate 16-vCPU host, 24 ms away, by 4–12 resource-capped load-generator containers (1–2 CPU each).
* **Mock upstream:** on the gateway VM itself, using up to 5 cores at peak. It waits 300 ms, then streams 31 events 20 ms apart, so the best possible latency is about 945 ms. "Steady" percentiles leave out the first 3 s, when hundreds of TLS connections open at once.

| Concurrent clients | Mode | Requests | Errors | Req/s | p50 | p95 | p99 | Proxy CPU / RSS |
|---|---|---|---|---|---|---|---|---|
| 100 | streaming | 4,700 | 0 | 103 | 948 ms | 953 | 954 | 0.4 core / 27 MB |
| 300 | streaming | 13,972 | 0 | 307 | 947 | 952 | 954 | 0.9 / 68 MB |
| 500 | streaming | 23,459 | 0 | 515 | 945 | 951 | 954 | 1.4 / 98 MB |
| 1,000 | streaming | 46,910 | 0 | 1,010 | 945 | 955 | 960 | 2.3 / 169 MB |
| 2,000 | streaming | 90,118 | 0 | 1,934 | 971 | 1,019 | 1,044 | 3.7 / 371 MB |
| 3,000 | streaming | 74,867 | 0 | 2,321 | 1,146 | 1,323 | 1,478 | 4.2 / 549 MB |
| 4,000 | streaming | 90,584 | 0 | 2,764 | 1,243 | 1,498 | 1,673 | 4.8 / 719 MB |
| 3,000 | non-streaming | 248,761 | 0 | **7,565** | 335 | 404 | 468 | 3.5 / 221 MB |

* **No request failed at any level.** Up to 1,000 concurrent streams the gateway adds about 15 ms at p99.
* **Above about 2,000 the shared VM ran out of CPU** (load average 16–22 on 16 cores, with the mock using about a third). Latency then rises gradually instead of requests failing.
* **In-process:** the full proxy path adds about 11 µs per request over a direct call, and the model scanner runs at about 1.5 GB/s.

### Real upstreams

| Upstream (model, API) | Concurrent clients | Requests | Errors | Req/s | p50 | p95 | p99 |
|---|---|---|---|---|---|---|---|
| PackyAPI (`gpt-6.1-terra`, Responses, streaming) | 100 | 1,101 | 0.18% | 35.9 | 2.2 s | 4.3 s | 7.3 s |
| | 200 | 1,981 | 0 | 64.9 | 2.3 s | 4.2 s | 9.6 s |
| | 300 | 3,078 | 0.16% | 99.5 | 2.4 s | 4.5 s | 6.8 s |
| OpenRouter (`mistralai/mistral-nemo`, chat, streaming) | 50 | 618 | 0 | 30.9 | 1.4 s | 2.4 s | 3.8 s |
| | 100 | 1,106 | 0 | 55.3 | 1.5 s | 3.2 s | 4.6 s |

* **Latency is the upstream's.** At 300 concurrent real streams the proxy used under half a core and about 40 MB.
* **The few PackyAPI errors** were streams that the relay ended without its `response.completed` event. The gateway saw a clean upstream close and logged no upstream error.
* **Cost:** about $1.47 on PackyAPI and $0.0007 on OpenRouter for all real-upstream testing.

### Token throughput (TPS)

Setup: PackyAPI `gpt-6.1-terra`, streaming Responses API, `reasoning.effort: low`, a prompt that asks for a ~250-word story (about 312 visible output tokens per request), 30 s per level (60 s at c=1).
* **Aggregate output** is all output tokens the upstream reported, reasoning included (1–5% here), divided by wall time.
* **Per-stream decode** is visible output tokens divided by the time from the first text token to the end of the stream.
* **TTFT** is time to the first text token.
* **Proxy CPU** is the share of one core.

| Concurrent streams | Requests | Errors | Aggregate output tok/s | Per-stream decode tok/s, p50 (p10–p90) | TTFT p50 / p95 | Latency p50 / p95 | Proxy CPU |
|---|---|---|---|---|---|---|---|
| 1 | 5 | 0 | 31 | 41 (35–42) | 2.7 s / 3.3 s | 10.8 s / 12.1 s | 1% |
| 10 | 22 | 0 | 240 | 42 (37–45) | 2.6 s / 4.5 s | 9.9 s / 11.2 s | 13% |
| 50 | 107 | 0 | 1,152 | 41 (38–45) | 2.7 s / 8.9 s | 9.9 s / 11.6 s | 27% |
| 100 | 207 | 0 | 2,167 | 39 (36–43) | 2.5 s / 3.9 s | 10.1 s / 11.8 s | 50% |
| 200 | 403 | 0 | 4,199 | 39 (35–42) | 2.6 s / 5.1 s | 10.4 s / 12.6 s | 66% |
| 300 | 622 | 0.16% | **6,460** | 40 (36–44) | 2.6 s / 7.6 s | 10.3 s / 12.9 s | 93% |

* **Per-stream speed stays at about 40 tok/s at every level, and aggregate TPS scales linearly** with the number of streams. The gateway adds no throughput ceiling in this range; the limit is the upstream model's decode speed, multiplied by how many streams the provider allows.
* **Cost:** 200,575 output tokens at c=300. The whole TPS ramp cost about $1.22.
* **To reproduce:** `tools/loadgen -api responses -stream -model gpt-6.1-terra -reasoning-effort low -prompt '…' -csv out.csv`. The CSV has `ttft_ms`, `out_tokens` and `reasoning_tokens` per request.

## 10. Running the tests

```bash
go test -race ./...                                    # unit + integration tests (mocked upstream)
go test -run '^$' -fuzz FuzzInspectJSON -fuzztime 30s ./internal/proxy/
go test -run '^$' -bench . ./internal/proxy/           # in-process overhead benchmarks
PYTHON=/path/to/python-with-openai scripts/e2e.sh      # local smoke test, SDK test, load benchmarks
```

To check a deployment with the OpenAI SDK:
```bash
PROXY_BASE_URL=https://host/v1 PROXY_TOKEN=sk-px-… PROXY_TOKEN_RESTRICTED=sk-px-… \
PROXY_MODEL=openai/gpt-4.1-nano PROXY_EMBED_MODEL=openai/text-embedding-3-small \
python tests/sdk/test_openai_sdk.py
```
Knobs: `PROXY_RESPONSES_MODEL`, `PROXY_RESTRICTED_MODELS`, `PROXY_EMBED_MODEL=` (skip embeddings), `PROXY_SKIP_RESPONSES_NONSTREAM=1` (relays with empty `output`), `PROXY_CONCURRENT_STREAMS`.

Load testing: `tools/loadgen` drives concurrent requests (`-c`, `-d`, `-stream`, `-api chat|responses`, `-model`, `-max-tokens`, `-reasoning-effort`, `-error-backoff`, `-csv`, `-json`). For streams it records latency, TTFB, time to first text token, and output and reasoning tokens from the final usage event, so TPS can be computed from the CSV. `tools/mockupstream` is the fake LLM; with host networking, `docker compose --profile mock up -d` starts it next to the gateway (`UPSTREAM_BASE_URL=http://127.0.0.1:19999/v1`, `ALLOW_INSECURE_UPSTREAM=true`). Against real upstreams, always set `-error-backoff`: workers that hit errors otherwise retry in a tight loop and can trigger provider rate limits.

## 11. Limitations

* **Stored-object access is account-wide.** All clients share one upstream account, so a client that knows another client's Responses ID (`resp_…`) could fetch, delete or continue it. The IDs are unguessable. If tenants must be fully isolated, remove the `/v1/responses/*` routes and tell clients to send `store: false`, or use one upstream account per tenant.
* **Model allow-lists check only the top-level `model` field.** They aren't a full spend policy: stored prompts (`prompt.id`), hosted tools (`image_generation` with its own model, `web_search`, `code_interpreter`, `file_search`) and pricing switches like `service_tier: "priority"` pass through unchecked.
* **Rate limits count requests, not tokens.** Limiter state is in memory and per instance, so several replicas multiply the effective limits.
* **Multipart endpoints** (audio, image edits, uploads) aren't in the default routes. If you enable them, only unrestricted tokens can use them.
* **Chat Completions stream usage is logged only if the client sends `stream_options: {"include_usage": true}`.**
* **WebSocket/Realtime endpoints aren't supported.**
* **Revocation edge case:** an invalid hand-edit of `tokens.json` keeps the *previous* file active, including tokens you meant to revoke. Use `scripts/keys.sh`.

## 12. Repository layout

```
cmd/oaiproxy/            binary: serve, token CLI, healthcheck
internal/proxy/          handler, routing, JSON model scanner, retries, limits, usage tap, metrics (+ tests)
internal/tokens/         token file format, hashing, rotation, signing keys, locked updates (+ tests)
internal/signing/        request-signature format, verification, replay cache (+ tests)
internal/admin/          admin HTTP API under /admin/ (+ tests)
clients/python/          pxclient: signing transport for httpx / the OpenAI SDK, `pxkey` CLI (+ tests)
internal/config/         environment configuration, upstream key file reloading (+ tests)
internal/mockupstream/   fake OpenAI API used by tests, the mock tool and benchmarks
tools/mockupstream/      standalone mock upstream (also shipped in the image, for load tests)
tools/loadgen/           load generator (chat/responses, streaming, CSV/JSON output)
tests/sdk/               OpenAI Python SDK compatibility test
scripts/setup.sh         one-time provider setup
scripts/keys.sh          client-token and upstream-key management
scripts/e2e.sh           local end-to-end smoke test + benchmarks
deploy/                  compose overrides (key file, admin key, host networking) and tokens.example.json
Dockerfile, docker-compose.yml, Caddyfile, .env.example
```
