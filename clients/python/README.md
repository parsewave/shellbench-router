# pxclient

`pxadmin`, a command-line tool for managing gateway tokens from your own machine (see the top-level README).

```bash
pip install "pxclient @ git+https://github.com/parsewave/shellbench-router.git#subdirectory=clients/python"
ssh -N -L 127.0.0.1:8081:127.0.0.1:8081 <ssh-user>@llm.example.com
export PX_PUBLIC_URL=https://llm.example.com/v1
export PX_ADMIN_URL=http://127.0.0.1:8081 PX_ADMIN_KEY=sk-pxadmin-...   # or PX_ADMIN_KEY_FILE
pxadmin add alice --allow-ips 203.0.113.7 --models gpt-4o-mini --expires 90d
pxadmin list
```

`PX_PUBLIC_URL` (or `--public-url`) is the model API base URL shown in token handoffs; it is separate from `PX_ADMIN_URL`. Local HTTP admin connections require it before creating or rotating a token.

`pxadmin -h` lists every command. From Python: `pxclient.Admin(url, key)`.

Tests: `pip install -e . pytest && pytest tests`.
