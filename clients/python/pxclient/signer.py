"""Ed25519 request signing (PX-ED25519-V1), matching internal/signing."""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import stat
import time
from pathlib import Path
from typing import Callable, Optional, Union

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

VERSION = "PX-ED25519-V1"
HEADER_TIMESTAMP = "X-Px-Timestamp"
HEADER_NONCE = "X-Px-Nonce"
HEADER_SIGNATURE = "X-Px-Signature"

PathLike = Union[str, "os.PathLike[str]"]


def string_to_sign(method: str, host: str, request_uri: str, ts: int, nonce: str, body: bytes) -> bytes:
    """The canonical message; must match the proxy byte for byte."""
    return "\n".join(
        [
            VERSION,
            method.upper(),
            host.lower(),
            request_uri,
            str(ts),
            nonce,
            hashlib.sha256(body).hexdigest(),
        ]
    ).encode()


def public_key_string(key: Ed25519PrivateKey) -> str:
    """The form the proxy admin registers: ``ed25519:<base64>``."""
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "ed25519:" + base64.b64encode(raw).decode()


def generate_key(path: PathLike, overwrite: bool = False) -> str:
    """Create a private key file (PEM, mode 0600) and return its public key string."""
    p = Path(path).expanduser()
    if p.exists() and not overwrite:
        raise FileExistsError(f"{p} already exists")
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(p, flags, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    os.chmod(p, 0o600)
    return public_key_string(key)


def load_private_key(path: PathLike) -> Ed25519PrivateKey:
    """Load a PEM private key (as written by generate_key or `openssl genpkey -algorithm ed25519`)."""
    p = Path(path).expanduser()
    mode = p.stat().st_mode
    if os.name == "posix" and mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise PermissionError(f"{p} is readable by other users; run: chmod 600 {p}")
    key = serialization.load_pem_private_key(p.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(f"{p} is not an Ed25519 private key")
    return key


class Signer:
    """Adds signature headers to httpx requests."""

    def __init__(
        self,
        key: Union[Ed25519PrivateKey, PathLike],
        clock: Callable[[], float] = time.time,
        nonce: Callable[[], str] = lambda: secrets.token_urlsafe(18),
    ):
        self.key = key if isinstance(key, Ed25519PrivateKey) else load_private_key(key)
        self._clock = clock
        self._nonce = nonce

    def headers(self, method: str, host: str, request_uri: str, body: bytes) -> dict:
        ts = int(self._clock())
        nonce = self._nonce()
        sig = self.key.sign(string_to_sign(method, host, request_uri, ts, nonce, body))
        return {
            HEADER_TIMESTAMP: str(ts),
            HEADER_NONCE: nonce,
            HEADER_SIGNATURE: base64.urlsafe_b64encode(sig).rstrip(b"=").decode(),
        }

    def sign(self, request: httpx.Request) -> None:
        body = request.read()  # buffers streaming bodies; the proxy buffers them too
        host = request.headers.get("host") or request.url.netloc.decode()
        request.headers.update(self.headers(request.method, host, request.url.raw_path.decode("ascii"), body))


class SigningTransport(httpx.BaseTransport):
    """httpx transport that signs every request (each retry gets a fresh nonce)."""

    def __init__(self, signer: Signer, transport: Optional[httpx.BaseTransport] = None):
        self.signer = signer
        self.transport = transport or httpx.HTTPTransport()

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.signer.sign(request)
        return self.transport.handle_request(request)

    def close(self) -> None:
        self.transport.close()


class AsyncSigningTransport(httpx.AsyncBaseTransport):
    """Async variant of SigningTransport."""

    def __init__(self, signer: Signer, transport: Optional[httpx.AsyncBaseTransport] = None):
        self.signer = signer
        self.transport = transport or httpx.AsyncHTTPTransport()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        await request.aread()
        self.signer.sign(request)
        return await self.transport.handle_async_request(request)

    async def aclose(self) -> None:
        await self.transport.aclose()
