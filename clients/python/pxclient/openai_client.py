"""OpenAI SDK clients that sign every request."""

from __future__ import annotations

import os
from typing import Any, Optional

import httpx

from .signer import AsyncSigningTransport, PathLike, Signer, SigningTransport


def _key_file(key_file: Optional[PathLike]) -> PathLike:
    key_file = key_file or os.environ.get("PX_KEY_FILE")
    if not key_file:
        raise ValueError("key_file is required (or set PX_KEY_FILE)")
    return key_file


def signed_openai(
    base_url: Optional[str] = None,
    api_key: Optional[str] = None,
    key_file: Optional[PathLike] = None,
    timeout: Any = httpx.Timeout(600.0, connect=10.0),
    **kwargs: Any,
):
    """openai.OpenAI whose requests are signed with key_file.

    base_url / api_key default to OPENAI_BASE_URL / OPENAI_API_KEY like the
    SDK itself; key_file defaults to PX_KEY_FILE.
    """
    import openai

    signer = Signer(_key_file(key_file))
    http_client = httpx.Client(transport=SigningTransport(signer), timeout=timeout)
    return openai.OpenAI(base_url=base_url, api_key=api_key, http_client=http_client, **kwargs)


def signed_async_openai(
    base_url: Optional[str] = None,
    api_key: Optional[str] = None,
    key_file: Optional[PathLike] = None,
    timeout: Any = httpx.Timeout(600.0, connect=10.0),
    **kwargs: Any,
):
    """openai.AsyncOpenAI whose requests are signed with key_file."""
    import openai

    signer = Signer(_key_file(key_file))
    http_client = httpx.AsyncClient(transport=AsyncSigningTransport(signer), timeout=timeout)
    return openai.AsyncOpenAI(base_url=base_url, api_key=api_key, http_client=http_client, **kwargs)
