"""OpenAI Python SDK compatibility check against a running proxy.

Only base_url and api_key differ from talking to OpenAI directly.

    PROXY_BASE_URL=http://127.0.0.1:8080/v1 \
    PROXY_TOKEN=sk-px-... PROXY_TOKEN_RESTRICTED=sk-px-... \
    python tests/sdk/test_openai_sdk.py

PROXY_TOKEN must be allowed to use PROXY_MODEL (chat), PROXY_RESPONSES_MODEL
and PROXY_EMBED_MODEL; PROXY_TOKEN_RESTRICTED must be limited to
PROXY_RESTRICTED_MODELS (default: PROXY_MODEL only).

Optional knobs for upstreams that differ from OpenAI:
  PROXY_EMBED_MODEL=""                skip the embeddings check
  PROXY_SKIP_RESPONSES_NONSTREAM=1    for relays whose final Response objects have an
                                      empty `output` (e.g. PackyAPI's codex channel):
                                      skip non-streaming Responses, and judge the
                                      streaming check by its text deltas only
  PROXY_CONCURRENT_STREAMS=N          size of the async concurrency check (50)
"""

import asyncio
import os
import sys

import openai
from openai import AsyncOpenAI, OpenAI

BASE = os.environ["PROXY_BASE_URL"]
TOKEN = os.environ["PROXY_TOKEN"]
RESTRICTED = os.environ["PROXY_TOKEN_RESTRICTED"]
MODEL = os.environ.get("PROXY_MODEL", "gpt-4o-mini")
RESPONSES_MODEL = os.environ.get("PROXY_RESPONSES_MODEL", MODEL)
EMBED_MODEL = os.environ.get("PROXY_EMBED_MODEL", "text-embedding-3-small")
RESTRICTED_MODELS = sorted(m for m in os.environ.get("PROXY_RESTRICTED_MODELS", MODEL).split(",") if m)
SKIP_RESPONSES_NONSTREAM = os.environ.get("PROXY_SKIP_RESPONSES_NONSTREAM") == "1"
CONCURRENT = int(os.environ.get("PROXY_CONCURRENT_STREAMS", "50"))

failures = []
passed = []


def check(name, fn):
    try:
        if fn() == "skip":
            print(f"SKIP  {name}")
            return
        passed.append(name)
        print(f"PASS  {name}")
    except Exception as e:  # noqa: BLE001
        failures.append(name)
        print(f"FAIL  {name}: {type(e).__name__}: {e}")


client = OpenAI(base_url=BASE, api_key=TOKEN, max_retries=0)


def chat_nonstream():
    r = client.chat.completions.create(model=MODEL, messages=[{"role": "user", "content": "Say hi"}])
    assert r.choices[0].message.content, r
    assert r.usage and r.usage.total_tokens > 0, r.usage


def chat_stream():
    chunks, text = 0, ""
    stream = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": "Count to five"}],
        stream=True,
        stream_options={"include_usage": True},
    )
    usage = None
    for ev in stream:
        chunks += 1
        if ev.choices and ev.choices[0].delta.content:
            text += ev.choices[0].delta.content
        if ev.usage:
            usage = ev.usage
    assert chunks > 1 and text, (chunks, text)
    assert usage is not None and usage.total_tokens > 0


def chat_tools():
    r = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": "What's the weather in Paris?"}],
        tools=[{
            "type": "function",
            "function": {"name": "get_weather", "parameters": {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]}},
        }],
        temperature=0,
    )
    assert r.choices, r


def responses_nonstream():
    if SKIP_RESPONSES_NONSTREAM:
        return "skip"
    r = client.responses.create(model=RESPONSES_MODEL, input="Say hi")
    assert r.output_text, r


def responses_stream():
    types, text = [], ""
    with client.responses.stream(model=RESPONSES_MODEL, input="Say hi") as s:
        for ev in s:
            types.append(ev.type)
            if ev.type == "response.output_text.delta":
                text += ev.delta
        final = s.get_final_response()
    assert "response.output_text.delta" in types and "response.completed" in types, types
    assert text, "no text deltas"
    assert final.status == "completed", final.status
    if not SKIP_RESPONSES_NONSTREAM:
        assert final.output_text, "final response has empty output"


def embeddings():
    if not EMBED_MODEL:
        return "skip"
    r = client.embeddings.create(model=EMBED_MODEL, input=["a", "b"])
    assert len(r.data) == 2 and len(r.data[0].embedding) > 0


def models_list():
    ids = [m.id for m in client.models.list()]
    assert MODEL in ids, ids


def restricted_models_list():
    ids = sorted(m.id for m in OpenAI(base_url=BASE, api_key=RESTRICTED, max_retries=0).models.list())
    assert ids == RESTRICTED_MODELS, ids


def invalid_token():
    bad = OpenAI(base_url=BASE, api_key="sk-px-invalid", max_retries=0)
    try:
        bad.chat.completions.create(model=MODEL, messages=[{"role": "user", "content": "x"}])
    except openai.AuthenticationError as e:
        assert e.status_code == 401
        return
    raise AssertionError("expected AuthenticationError")


def disallowed_model():
    r = OpenAI(base_url=BASE, api_key=RESTRICTED, max_retries=0)
    try:
        r.chat.completions.create(model="o3", messages=[{"role": "user", "content": "x"}])
    except openai.PermissionDeniedError as e:
        assert e.status_code == 403 and e.code == "model_not_allowed", e
        return
    raise AssertionError("expected PermissionDeniedError")


def async_concurrent():
    async def run():
        ac = AsyncOpenAI(base_url=BASE, api_key=TOKEN, max_retries=0)
        async def one(i):
            s = await ac.chat.completions.create(model=MODEL, messages=[{"role": "user", "content": f"#{i}"}], stream=True)
            n = 0
            async for _ in s:
                n += 1
            return n
        res = await asyncio.gather(*(one(i) for i in range(CONCURRENT)))
        await ac.close()
        assert all(n > 1 for n in res), res
    asyncio.run(run())


for name, fn in [
    ("chat.completions (non-stream)", chat_nonstream),
    ("chat.completions (stream + usage)", chat_stream),
    ("chat.completions (tools)", chat_tools),
    ("responses (non-stream)", responses_nonstream),
    ("responses (stream)", responses_stream),
    ("embeddings", embeddings),
    ("models.list", models_list),
    ("models.list filtered for restricted token", restricted_models_list),
    ("invalid token -> AuthenticationError 401", invalid_token),
    ("disallowed model -> PermissionDeniedError 403", disallowed_model),
    (f"{CONCURRENT} concurrent async streams", async_concurrent),
]:
    check(name, fn)

print(f"\nopenai-python {openai.__version__}: {len(passed)} passed, {len(failures)} failed")
sys.exit(1 if failures else 0)
