# shellbench-router

Share one model-provider API key (OpenAI, OpenRouter, PackyAPI, or any OpenAI-compatible API) with many people and harnesses **without handing out the key**. You run this gateway on a server. Everyone else gets their own `sk-px-…` token and uses it like a normal OpenAI key. Each token can be revoked, rotated, expired, rate-limited, limited to certain models, and locked to certain IP addresses.

```
your users / Harbor ──HTTPS──▶ gateway (your server) ──▶ provider API
   sk-px-… token                 holds the real key
```

---

## 1. Set up the gateway (once, about 5 minutes)

You need a Linux server with Docker, and ports 80 and 443 open to the internet. You don't need a domain name.

```bash
git clone https://github.com/parsewave/shellbench-router.git
cd shellbench-router
scripts/setup.sh
```

It asks three questions:

1. **Provider:** `openai`, `openrouter`, `packy`, or `custom` (any OpenAI-compatible URL).
2. **Hostname:** press Enter to get a free `https://<your-ip>.sslip.io` address with a real HTTPS certificate.
3. **Your provider API key:** input is hidden. It's stored on the server only.

At the end it prints two things. Save both:

```
Done. Gateway: https://203-0-113-7.sslip.io/v1
Admin key (shown once; put it in your password manager):
  sk-pxadmin-...
```

## 2. Install the admin tool on your own computer

```bash
pip install "pxclient @ git+https://github.com/parsewave/shellbench-router.git#subdirectory=clients/python"

export PX_ADMIN_URL=https://203-0-113-7.sslip.io     # your gateway, without /v1
export PX_ADMIN_KEY=sk-pxadmin-...                   # the admin key from step 1

pxadmin list                                         # should print "no users yet"
```

## 3. Give someone access

Find out the IP address their requests will come from (they can run `curl -s https://api.ipify.org` on that machine). Then:

```bash
pxadmin add alice --allow-ips 198.51.100.24 --models gpt-4o-mini --expires 90d
```

It prints a message to send them, containing the base URL, their token and their models. That's it.

* `--allow-ips` locks the token to those addresses, so a leaked copy is useless anywhere else. It takes several values separated by commas, including ranges: `198.51.100.24,10.0.0.0/8`. If you leave it out, the token works from any IP.
* If you leave out `--models`, every model is allowed. Each user gets 16 concurrent requests unless you set `--concurrency`.

## 4. Use it

Any OpenAI SDK, tool or harness works. Change only two settings:

```bash
export OPENAI_BASE_URL=https://203-0-113-7.sslip.io/v1
export OPENAI_API_KEY=sk-px-...
```

```python
from openai import OpenAI
client = OpenAI(base_url="https://203-0-113-7.sslip.io/v1", api_key="sk-px-...")
print(client.responses.create(model="gpt-4o-mini", input="hi").output_text)
```

---

## Running Harbor through the gateway

Tested with Harbor 0.9 and the `codex` agent.

**1. Create a token for the machine that runs Harbor.**

```bash
pxadmin add harbor --allow-ips <harbor-machine-ip> --models gpt-6.1-terra --concurrency 32 --expires 30d
```

If Harbor runs **on the gateway server itself**, the trial containers reach the gateway from Docker addresses, so allow those too: `--allow-ips <server-ip>,172.16.0.0/12`.

**2. Run the trial with these variables:**

```bash
export OPENAI_BASE_URL=https://203-0-113-7.sslip.io/v1
export OPENAI_API_KEY=sk-px-...          # the harbor token
export HARBOR_ALLOW_INTERNET=1           # let the agent reach the gateway directly

harbor trial start -p path/to/task -a codex -m openai/gpt-6.1-terra
```

## Everyday commands

```bash
pxadmin list                                   # everyone: status, allowed IPs, models, limits, expiry
pxadmin revoke alice                           # cut off now      (pxadmin enable alice to undo)
pxadmin rotate alice --grace 24h               # new token; old one keeps working for 24h
pxadmin set alice --allow-ips 198.51.100.24,203.0.113.0/24 --models '*'
pxadmin remove alice
```

On the server you can do the same with `scripts/keys.sh` (`scripts/keys.sh list`, `scripts/keys.sh add -id alice -allow-ips 198.51.100.24`, …). `docker compose logs -f proxy` shows every request with its user, IP, status and token usage.

**Updating the gateway:** `git pull && docker compose up -d --build` on the server.

## If something fails

| You see | Fix |
|---|---|
| `401 invalid_api_key` | Wrong, expired or revoked token. Check with `pxadmin list`. |
| `403 ip_not_allowed` | The message says which IP the gateway saw. Add it: `pxadmin set NAME --allow-ips <old>,<new>`. |
| `403 model_not_allowed` | `pxadmin set NAME --models <list>`, or `'*'` for all models. |
| `429` | The user hit their rate or concurrency limit. The SDK retries; raise it with `--concurrency` / `--rpm`. |
| `protocol_not_supported` | The provider doesn't serve that model over this API. Use the Responses API, or an agent like `codex`. |
| Harbor: "Reconnecting… error sending request" or "access token could not be refreshed" | Use the Harbor variables above (`HARBOR_ALLOW_INTERNET=1`, empty `HOME`, no Parsewave token). |
| `setup.sh`: HTTPS not reachable | Open ports 80 and 443. Check `docker compose logs caddy`. |

---

Everything else is in **[docs/reference.md](docs/reference.md)**: every setup option, the admin HTTP API, all configuration variables, the security model, reliability behaviour, logging and metrics, test results, and the repository layout.
