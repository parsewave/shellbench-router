"""pxkey: manage the local request-signing key.

    pxkey generate [--out ~/.pxkey/private.pem]   create a key; prints the public key
    pxkey public   [--key ~/.pxkey/private.pem]   print the public key again
"""

from __future__ import annotations

import argparse
import sys

from .signer import generate_key, load_private_key, public_key_string

DEFAULT = "~/.pxkey/private.pem"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="pxkey", description="Manage the shellbench proxy request-signing key.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate", help="create a new private key and print its public key")
    g.add_argument("--out", default=DEFAULT)
    g.add_argument("--force", action="store_true", help="overwrite an existing key file")
    p = sub.add_parser("public", help="print the public key of an existing private key")
    p.add_argument("--key", default=DEFAULT)
    args = ap.parse_args(argv)

    if args.cmd == "generate":
        try:
            pub = generate_key(args.out, overwrite=args.force)
        except FileExistsError as e:
            print(f"error: {e} (use --force to replace it)", file=sys.stderr)
            return 1
        print(f"Private key written to {args.out} (keep it on this machine; never share it).", file=sys.stderr)
        print("Send this public key to the proxy admin:", file=sys.stderr)
        print(pub)
        return 0
    print(public_key_string(load_private_key(args.key)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
