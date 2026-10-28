"""pxadmin: manage gateway tokens from your own machine via the admin API.

    # Use SSH forwarding when administering from your own machine.
    export PX_PUBLIC_URL=https://llm.example.com/v1
    export PX_ADMIN_URL=http://127.0.0.1:8081 PX_ADMIN_KEY=sk-pxadmin-...

    pxadmin add alice --allow-ips 203.0.113.7 --models gpt-4o-mini --expires 90d
    pxadmin list
    pxadmin show alice
    pxadmin set alice --allow-ips 203.0.113.7,10.0.0.0/8 --rpm 600 --models '*'
    pxadmin rotate alice --grace 24h
    pxadmin revoke alice | enable alice | remove alice
"""

from __future__ import annotations

import argparse
import os
import sys
from urllib.parse import urlsplit
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

    def add(self, id: str, **fields: Any) -> dict:
        return self._call("POST", "/clients", {"id": id, **{k: v for k, v in fields.items() if v is not None}})

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

def _models(s: Optional[str]):
    if s is None:
        return None
    return [m.strip() for m in s.split(",") if m.strip() and m.strip() != "*"]


def _limits(args) -> dict:
    return {
        "models": _models(args.models),
        "allowed_ips": _models(args.allow_ips),
        "rpm": args.rpm,
        "burst": args.burst,
        "max_concurrent": args.concurrency,
        "expires": args.expires,
        "note": args.note,
    }


def _status(c: dict) -> str:
    return (
        f"{c['id']}: {c['status']}, ips={','.join(c['allowed_ips']) or 'any'}, models={','.join(c['models']) or '*'}, "
        f"rpm={c['rpm'] or '-'}, concurrency={c['max_concurrent'] or '-'}, expires={c.get('expires_at') or 'never'}"
    )


def _handoff(base: str, c: dict, token: str) -> str:
    models = ", ".join(c["models"]) or "all models"
    if c["allowed_ips"]:
        where = f"It only works from {', '.join(c['allowed_ips'])}, so a leaked copy is useless elsewhere."
    else:
        where = "It works from any IP: anyone with a copy can use it until you revoke it (consider --allow-ips)."
    return f"""Send this to {c['id']} (the token is shown only once):

  Base URL: {base}
  API key:  {token}
  Models:   {models}

  Works with any OpenAI SDK or tool: set OPENAI_BASE_URL and OPENAI_API_KEY.

{where}"""


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
    ap.add_argument("--public-url", help="public model API base URL for token handoffs (default $PX_PUBLIC_URL)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def limits(p, create=False):
        p.add_argument("--allow-ips", help="comma-separated IPs / CIDR ranges the token works from; '*' = any")
        p.add_argument("--models", help="comma-separated allow-list, prefix* globs; '*' = all")
        p.add_argument("--rpm", type=int, help="requests per minute (0 = unlimited)")
        p.add_argument("--burst", type=int)
        p.add_argument("--concurrency", type=int, help="max in-flight requests" + (" (default 16)" if create else ""))
        p.add_argument("--expires", help="90d, 12h, 2027-01-31, RFC3339, or never")
        p.add_argument("--note")

    p = sub.add_parser("add", help="create a user and print their token")
    p.add_argument("id")
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
    args = ap.parse_args(argv)

    a = admin or _connect(args)
    if args.cmd in ("add", "rotate"):
        public = args.public_url or os.environ.get("PX_PUBLIC_URL")
        # A tunnel's admin address is not a usable model endpoint. Validate
        # before issuing a token so an error cannot strand its one-time value.
        if not public:
            parsed = urlsplit(a.url)
            if parsed.scheme != "https" or parsed.hostname in ("localhost", "127.0.0.1", "::1"):
                ap.error("set PX_PUBLIC_URL or --public-url to the public model API base URL")
            public = a.url + "/v1"
        parsed = urlsplit(public)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username is not None or parsed.query or parsed.fragment:
            ap.error("public model API URL must use http(s), with no credentials, query, or fragment")
        public = public.rstrip("/")
    try:
        if args.cmd == "add":
            fields = _limits(args)
            if fields["max_concurrent"] is None:
                fields["max_concurrent"] = 16
            out = a.add(args.id, **fields)
            print(_handoff(public, out["client"], out["token"]), file=sys.stderr)
            print(out["token"])
        elif args.cmd == "list":
            clients = a.list()
            for c in clients:
                print(_status(c))
            if not clients:
                print("no users yet; create one with: pxadmin add ID --allow-ips THEIR_IP", file=sys.stderr)
        elif args.cmd == "show":
            print(_status(a.show(args.id)))
        elif args.cmd == "set":
            print(_status(a.set(args.id, **_limits(args))))
        elif args.cmd == "rotate":
            out = a.rotate(args.id, args.grace)
            print(_handoff(public, out["client"], out["token"]), file=sys.stderr)
            print(out["token"])
        elif args.cmd in ("revoke", "enable"):
            print(_status(getattr(a, args.cmd)(args.id)))
        elif args.cmd == "remove":
            a.remove(args.id)
            print(f"removed {args.id}", file=sys.stderr)
    except AdminError as e:
        print(f"error: {e.message}", file=sys.stderr)
        return 1
    except httpx.HTTPError as e:
        print(f"error: cannot reach {a.url}: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
