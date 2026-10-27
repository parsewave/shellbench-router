"""Request signing for the shellbench proxy.

A client with a registered Ed25519 key must sign every request in addition
to sending its proxy token (see internal/signing in the proxy). This package
does that transparently for httpx and the OpenAI SDK::

    from pxclient import signed_openai
    client = signed_openai(base_url="https://proxy.example.com/v1",
                           api_key="sk-px-...", key_file="~/.pxkey/private.pem")
    client.responses.create(model="gpt-4o", input="hi")

Generate a key pair with ``pxkey generate`` and give the printed public key
(not the private key file) to the proxy admin.
"""

from .signer import (
    HEADER_NONCE,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    VERSION,
    AsyncSigningTransport,
    Signer,
    SigningTransport,
    generate_key,
    load_private_key,
    public_key_string,
    string_to_sign,
)
from .admin import Admin, AdminError
from .openai_client import signed_async_openai, signed_openai

__all__ = [
    "Admin",
    "AdminError",
    "HEADER_NONCE",
    "HEADER_SIGNATURE",
    "HEADER_TIMESTAMP",
    "VERSION",
    "AsyncSigningTransport",
    "Signer",
    "SigningTransport",
    "generate_key",
    "load_private_key",
    "public_key_string",
    "string_to_sign",
    "signed_openai",
    "signed_async_openai",
]
