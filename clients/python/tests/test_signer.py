import base64
import json
import os
import stat

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pxclient import (
    HEADER_NONCE,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    AsyncSigningTransport,
    Signer,
    SigningTransport,
    generate_key,
    load_private_key,
    public_key_string,
    string_to_sign,
)
from pxclient.cli import main as pxkey

# Shared with internal/signing/signing_test.go (seed bytes 00..1f).
VECTOR_PUB = "ed25519:A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg="
VECTOR_MSG = (
    "PX-ED25519-V1\nPOST\nproxy.example.com\n/v1/responses?x=1\n1793093230\nnonce-0123456789abcdef\n"
    "afdd3df91505360960ddc9dc239b4cd1b771d5d990e5881599da557d56dc8677"
)
VECTOR_SIG = "9hfW4A5m7JaiWesAubRjlGDYJCH5BZv7IL-DNT4T-IL0kFbgCMsvJKN1z1zrGpleMoFzwPKqHFfQjnODwQ9JDg"
VECTOR_BODY = b'{"model":"gpt-4o","input":"hi"}'


def vector_key():
    return Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


def test_vector_matches_go():
    key = vector_key()
    assert public_key_string(key) == VECTOR_PUB
    msg = string_to_sign("post", "Proxy.Example.com", "/v1/responses?x=1", 1793093230, "nonce-0123456789abcdef", VECTOR_BODY)
    assert msg.decode() == VECTOR_MSG
    s = Signer(key, clock=lambda: 1793093230.9, nonce=lambda: "nonce-0123456789abcdef")
    h = s.headers("POST", "proxy.example.com", "/v1/responses?x=1", VECTOR_BODY)
    assert h == {HEADER_TIMESTAMP: "1793093230", HEADER_NONCE: "nonce-0123456789abcdef", HEADER_SIGNATURE: VECTOR_SIG}


def _verify(request: httpx.Request, key: Ed25519PrivateKey):
    sig = base64.urlsafe_b64decode(request.headers[HEADER_SIGNATURE] + "==")
    msg = string_to_sign(
        request.method,
        request.headers["host"],
        request.url.raw_path.decode(),
        int(request.headers[HEADER_TIMESTAMP]),
        request.headers[HEADER_NONCE],
        request.content,
    )
    key.public_key().verify(sig, msg)  # raises InvalidSignature


def test_transport_signs_each_request():
    key = Ed25519PrivateKey.generate()
    seen = []

    def handler(request):
        _verify(request, key)
        seen.append(request.headers[HEADER_NONCE])
        return httpx.Response(200, json={"ok": True})

    client = httpx.Client(transport=SigningTransport(Signer(key), httpx.MockTransport(handler)))
    client.post("https://proxy.example.com:8443/v1/chat/completions?a=b%20c", json={"model": "m"})
    client.get("https://proxy.example.com/v1/models")
    # Streaming request bodies are buffered so they can be hashed.
    client.post("https://proxy.example.com/v1/embeddings", content=iter([b'{"input":', b'"x"}']))
    assert len(seen) == 3 and len(set(seen)) == 3


async def test_async_transport():
    key = Ed25519PrivateKey.generate()

    def handler(request):
        _verify(request, key)
        return httpx.Response(200, json={})

    async with httpx.AsyncClient(transport=AsyncSigningTransport(Signer(key), httpx.MockTransport(handler))) as c:
        r = await c.post("https://proxy.example.com/v1/responses", json={"model": "m", "input": "hi"})
        assert r.status_code == 200


def test_generate_and_load(tmp_path, capsys):
    path = tmp_path / "k" / "private.pem"
    assert pxkey(["generate", "--out", str(path)]) == 0
    pub = capsys.readouterr().out.strip()
    assert pub.startswith("ed25519:")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert public_key_string(load_private_key(path)) == pub
    assert pxkey(["generate", "--out", str(path)]) == 1  # refuses to overwrite
    assert pxkey(["public", "--key", str(path)]) == 0
    assert capsys.readouterr().out.strip() == pub


def test_refuses_world_readable_key(tmp_path):
    path = tmp_path / "private.pem"
    generate_key(path)
    os.chmod(path, 0o644)
    with pytest.raises(PermissionError):
        load_private_key(path)
