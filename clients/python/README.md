# pxclient

Client tools for the shellbench gateway (see "Getting started" in the top-level README).

```bash
pip install "pxclient[openai] @ git+https://github.com/parsewave/shellbench-router.git#subdirectory=clients/python"
```

**Users**: `pxkey generate` creates `~/.pxkey/private.pem` (0600) and prints the public key to send to the admin. Then:

```python
from pxclient import signed_openai          # signed_async_openai for AsyncOpenAI
client = signed_openai(base_url="https://llm.example.com/v1", api_key="sk-px-…", key_file="~/.pxkey/private.pem")
```

`base_url`, `api_key` and `key_file` default to `OPENAI_BASE_URL`, `OPENAI_API_KEY` and `PX_KEY_FILE`. For plain httpx, use `httpx.Client(transport=SigningTransport(Signer("~/.pxkey/private.pem")))`.

**Admins**: set `PX_ADMIN_URL` and `PX_ADMIN_KEY` (or `PX_ADMIN_KEY_FILE`), then run `pxadmin add alice --pubkey ed25519:...`, `pxadmin list`, `pxadmin revoke alice`, and so on (`pxadmin -h` lists every command). From Python: `pxclient.Admin(url, key)`.

Tests: `pip install -e .[openai] pytest && pytest tests`. `tests/test_signer.py` shares a fixed test vector with `internal/signing/signing_test.go`, so both implementations must produce byte-identical signatures.
