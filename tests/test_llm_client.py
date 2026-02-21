from __future__ import annotations

import os

import pytest

from secure_inspector.llm_client import LLMClient


def test_llm_client_accepts_api_key_override(monkeypatch):
    pytest.importorskip("openai")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    client = LLMClient(
        model="gpt-4.1-mini",
        temperature=0.1,
        max_tokens=256,
        max_retries=0,
        strict_json=True,
        api_key="test-key",
    )
    assert client.model == "gpt-4.1-mini"
    assert not os.getenv("OPENAI_API_KEY")

