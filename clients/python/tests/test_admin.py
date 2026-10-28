import json

import httpx
import pytest

from pxclient.admin import Admin, main

CLIENT = {
    "id": "alice", "status": "active", "models": ["gpt-4o-mini"], "rpm": 0, "burst": 0, "max_concurrent": 16,
    "allowed_ips": ["203.0.113.7"], "secrets": [],
}


def admin(handler):
    return Admin("https://gw.example/v1", "sk-pxadmin-test", httpx.Client(transport=httpx.MockTransport(handler)))


def test_add_prints_token_and_handoff(capsys):
    seen = {}

    def handler(r):
        seen.update(method=r.method, url=str(r.url), auth=r.headers["authorization"], body=json.loads(r.content))
        return httpx.Response(201, json={"client": CLIENT, "token": "sk-px-TOKEN"})

    rc = main(["add", "alice", "--allow-ips", "203.0.113.7", "--models", "gpt-4o-mini"], admin=admin(handler))
    out, err = capsys.readouterr()
    assert rc == 0 and out.strip() == "sk-px-TOKEN"
    assert seen["url"] == "https://gw.example/admin/clients" and seen["auth"] == "Bearer sk-pxadmin-test"
    assert seen["body"] == {"id": "alice", "allowed_ips": ["203.0.113.7"], "models": ["gpt-4o-mini"], "max_concurrent": 16}
    assert "only works from 203.0.113.7" in err and "https://gw.example/v1" in err


def test_set_all_models_and_errors(capsys):
    bodies = []

    def handler(r):
        bodies.append(json.loads(r.content) if r.content else None)
        if r.method == "PATCH":
            return httpx.Response(200, json=CLIENT)
        return httpx.Response(404, json={"error": {"code": "not_found", "message": 'client "bob" not found'}})

    a = admin(handler)
    assert main(["set", "alice", "--models", "*", "--allow-ips", "*", "--rpm", "600"], admin=a) == 0
    assert bodies[0] == {"models": [], "allowed_ips": [], "rpm": 600}
    assert main(["revoke", "bob"], admin=a) == 1
    assert 'client "bob" not found' in capsys.readouterr().err


@pytest.mark.parametrize("command", ["add", "rotate"])
def test_private_admin_public_handoff(command, capsys, monkeypatch):
    seen = []
    def handler(r):
        seen.append(str(r.url))
        return httpx.Response(201 if command == "add" else 200, json={"client": CLIENT, "token": "sk-px-TOKEN"})
    a = Admin("http://127.0.0.1:8081", "fixture", httpx.Client(transport=httpx.MockTransport(handler)))
    monkeypatch.setenv("PX_PUBLIC_URL", "https://models.example/v1")
    assert main([command, "alice"], admin=a) == 0
    assert seen[0].startswith("http://127.0.0.1:8081/admin/")
    out, err = capsys.readouterr()
    assert out.strip() == "sk-px-TOKEN"
    assert "Base URL: https://models.example/v1" in err and "8081/v1" not in err


@pytest.mark.parametrize("public", [None, "https://user:secret@models.example/v1", "file:///tmp/api", "https://models.example/v1?key=secret"])
def test_handoff_url_validated_before_token_creation(public, monkeypatch):
    monkeypatch.delenv("PX_PUBLIC_URL", raising=False)
    def handler(r):
        pytest.fail("invalid handoff must not issue or rotate a token")
    a = Admin("http://127.0.0.1:8081", "fixture", httpx.Client(transport=httpx.MockTransport(handler)))
    args = (["--public-url", public] if public else []) + ["add", "alice"]
    with pytest.raises(SystemExit):
        main(args, admin=a)
