"""pxadmin: manage gateway tokens from your own machine via the admin API.

    export PX_ADMIN_URL=https://llm.example.com PX_ADMIN_KEY=sk-pxadmin-...

    pxadmin add alice --pubkey ed25519:... --models gpt-4o-mini --concurrency 16 --expires 90d
    pxadmin add ci-bot --unsigned --concurrency 4        # plain token, for tools that can't sign
    pxadmin list
    pxadmin show alice
    pxadmin set alice --rpm 600 --models '*'
    pxadmin rotate alice --grace 24h
    pxadmin revoke alice | enable alice | remove alice
    pxadmin add-key alice --pubkey ed25519:...           # e.g. a second machine
    pxadmin remove-key alice k_0123456789ab [--allow-unsigned]
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any, Optional

import httpx


class AdminError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(f"{message} ({status} {code})")
        self.status, self.code, self.message = status, code, message


class Admin:
    """Thin client for the gateway's /admin API."""

    def __init__(self, url: str, key: str, client: Optional[httpx.Client] = None):
        self.url = url.rstrip("/")
        if self.url.endswith("/v1"):
            self.url = self.url[:-3]
        self.http = client or httpx.Client(timeout=30)
        self.headers = {"Authorization": f"Bearer {key}"}

    def _call(self, method: str, path: str, body: Optional[dict] = None, params: Optional[dict] = None) -> Any:
        r = self.http.request(method, self.url + "/admin" + path, json=body, params=params, headers=self.headers)
        data = r.json() if r.content else None
        if r.status_code >= 400:
            err = (data or {}).get("error", {}) if isinstance(data, dict) else {}
            raise AdminError(r.status_code, err.get("code", "error"), err.get("message", r.text))
        return data

    def list(self) -> list:
        return self._call("GET", "/clients")["clients"]

    def show(self, id: str) -> dict:
        return self._call("GET", f"/clients/{id}")

    def add(self, id: str, public_key: Optional[str] = None, unsigned: bool = False, **fields: Any) -> dict:
        body = {"id": id, **{k: v for k, v in fields.items() if v is not None}}
        if public_key:
            body["public_key"] = public_key
        if unsigned:
            body["unsigned"] = True
        return self._call("POST", "/clients", body)

    def set(self, id: str, **fields: Any) -> dict:
        return self._call("PATCH", f"/clients/{id}", {k: v for k, v in fields.items() if v is not None})

    def rotate(self, id: str, grace: Optional[str] = None) -> dict:
        return self._call("POST", f"/clients/{id}/rotate", {"grace": grace} if grace else {})

    def revoke(self, id: str) -> dict:
        return self._call("POST", f"/clients/{id}/revoke")

    def enable(self, id: str) -> dict:
        return self._call("POST", f"/clients/{id}/enable")

    def remove(self, id: str) -> None:
        self._call("DELETE", f"/clients/{id}")

    def add_key(self, id: str, public_key: str, note: str = "", expires: str = "") -> dict:
        return self._call("POST", f"/clients/{id}/keys", {"public_key": public_key, "note": note, "expires": expires})

    def remove_key(self, id: str, key_id: str, allow_unsigned: bool = False) -> None:
        self._call("DELETE", f"/clients/{id}/keys/{key_id}", params={"allow_unsigned": "true"} if allow_unsigned else None)


def _models(s: Optional[str]):
    if s is None:
        return None
    return [m.strip() for m in s.split(",") if m.strip() and m.strip() != "*"]


def _limits(args) -> dict:
    return {
        "models": _models(args.models),
        "rpm": args.rpm,
        "burst": args.burst,
        "max_concurrent": args.concurrency,
        "expires": args.expires,
        "note": args.note,
    }


def _status(c: dict) -> str:
    signed = "signed (" + ", ".join(k["id"] for k in c["public_keys"]) + ")" if c["public_keys"] else "UNSIGNED"
    return (
        f"{c['id']}: {c['status']}, {signed}, models={','.join(c['models']) or '*'}, "
        f"rpm={c['rpm'] or '-'}, concurrency={c['max_concurrent'] or '-'}, expires={c.get('expires_at') or 'never'}"
    )


def _handoff(admin: Admin, c: dict, token: str) -> str:
    base = admin.url + "/v1"
    models = ", ".join(c["models"]) or "all models"
    if c["public_keys"]:
        return f"""Send this to {c['id']} (the token is shown only once):

  Base URL: {base}
  API key:  {token}
  Models:   {models}

  from pxclient import signed_openai
  client = signed_openai(base_url="{base}", api_key="<API key>", key_file="~/.pxkey/private.pem")

The token only works together with their private key, so it is useless to anyone else."""
    return f"""Send this to {c['id']} (the token is shown only once):

  Base URL: {base}
  API key:  {token}
  Models:   {models}

  Works with any OpenAI SDK or tool (OPENAI_BASE_URL / OPENAI_API_KEY).

This token is UNSIGNED: anyone who gets a copy can use it until you revoke it."""


def _connect(args) -> Admin:
    url = args.url or os.environ.get("PX_ADMIN_URL")
    key = args.key or os.environ.get("PX_ADMIN_KEY")
    key_file = os.environ.get("PX_ADMIN_KEY_FILE")
    if not key and key_file:
        key = Path(key_file).expanduser().read_text().strip()
    if not url or not key:
        raise SystemExit("error: set PX_ADMIN_URL and PX_ADMIN_KEY (or PX_ADMIN_KEY_FILE), or pass --url/--key")
    return Admin(url, key)


def main(argv=None, admin: Optional[Admin] = None) -> int:
    ap = argparse.ArgumentParser(prog="pxadmin", description="Manage shellbench gateway tokens.",
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--url", help="gateway URL (default $PX_ADMIN_URL)")
    ap.add_argument("--key", help="admin key (default $PX_ADMIN_KEY or the file in $PX_ADMIN_KEY_FILE)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def limits(p, create=False):
        p.add_argument("--models", help="comma-separated allow-list, prefix* globs; '*' = all")
        p.add_argument("--rpm", type=int, help="requests per minute (0 = unlimited)")
        p.add_argument("--burst", type=int)
        p.add_argument("--concurrency", type=int, help="max in-flight requests" + (" (default 16)" if create else ""))
        p.add_argument("--expires", help="90d, 12h, 2027-01-31, RFC3339, or never")
        p.add_argument("--note")

    p = sub.add_parser("add", help="create a user and print their token")
    p.add_argument("id")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--pubkey", help="the user's public key from `pxkey generate` (signed token)")
    g.add_argument("--unsigned", action="store_true", help="plain bearer token, for tools that can't sign")
    limits(p, create=True)
    sub.add_parser("list", help="list users")
    p = sub.add_parser("show", help="show one user")
    p.add_argument("id")
    p = sub.add_parser("set", help="change models, limits, expiry or note")
    p.add_argument("id")
    limits(p)
    p = sub.add_parser("rotate", help="issue a new token")
    p.add_argument("id")
    p.add_argument("--grace", help="how long the old token keeps working, e.g. 24h (default: revoke now)")
    for name, help_ in [("revoke", "disable immediately"), ("enable", "re-enable"), ("remove", "delete")]:
        sub.add_parser(name, help=help_).add_argument("id")
    p = sub.add_parser("add-key", help="register another signing key for a user")
    p.add_argument("id")
    p.add_argument("--pubkey", required=True)
    p.add_argument("--note", default="")
    p.add_argument("--expires", default="")
    p = sub.add_parser("remove-key", help="remove a signing key")
    p.add_argument("id")
    p.add_argument("key_id")
    p.add_argument("--allow-unsigned", action="store_true", help="allow removing the last key (turns signing off)")
    args = ap.parse_args(argv)

    a = admin or _connect(args)
    try:
        if args.cmd == "add":
            fields = _limits(args)
            if fields["max_concurrent"] is None:
                fields["max_concurrent"] = 16
            out = a.add(args.id, public_key=args.pubkey, unsigned=args.unsigned, **fields)
            print(_handoff(a, out["client"], out["token"]), file=sys.stderr)
            print(out["token"])
        elif args.cmd == "list":
            clients = a.list()
            for c in clients:
                print(_status(c))
            if not clients:
                print("no users yet; create one with: pxadmin add ID --pubkey ed25519:...", file=sys.stderr)
        elif args.cmd == "show":
            print(_status(a.show(args.id)))
        elif args.cmd == "set":
            print(_status(a.set(args.id, **_limits(args))))
        elif args.cmd == "rotate":
            out = a.rotate(args.id, args.grace)
            print(_handoff(a, out["client"], out["token"]), file=sys.stderr)
            print(out["token"])
        elif args.cmd in ("revoke", "enable"):
            print(_status(getattr(a, args.cmd)(args.id)))
        elif args.cmd == "remove":
            a.remove(args.id)
            print(f"removed {args.id}", file=sys.stderr)
        elif args.cmd == "add-key":
            out = a.add_key(args.id, args.pubkey, args.note, args.expires)
            print(_status(out["client"]))
        elif args.cmd == "remove-key":
            a.remove_key(args.id, args.key_id, args.allow_unsigned)
            print(f"removed key {args.key_id} from {args.id}", file=sys.stderr)
    except AdminError as e:
        print(f"error: {e.message}", file=sys.stderr)
        return 1
    except httpx.HTTPError as e:
        print(f"error: cannot reach {a.url}: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
