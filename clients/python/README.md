# pxclient

Signs requests for the shellbench proxy (see "Request signing" in the top-level README).

```bash
pip install ./clients/python[openai]
pxkey generate                  # ~/.pxkey/private.pem (0600); prints the public key for the admin
```

```python
from pxclient import signed_openai
client = signed_openai(base_url="https://llm.example.com/v1", api_key="sk-px-…", key_file="~/.pxkey/private.pem")
```

`base_url` / `api_key` / `key_file` default to `OPENAI_BASE_URL`, `OPENAI_API_KEY` and `PX_KEY_FILE`. For plain httpx use `httpx.Client(transport=SigningTransport(Signer("~/.pxkey/private.pem")))`.

Tests: `pip install -e .[openai] pytest && pytest tests`. `tests/test_signer.py` shares a fixed test vector with `internal/signing/signing_test.go`, so both implementations must produce byte-identical signatures.
