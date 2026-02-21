from __future__ import annotations

import json
import os
import re
from typing import Any

try:
    from openai import OpenAI
except ImportError:  # pragma: no cover
    OpenAI = None  # type: ignore[assignment]


_JSON_BLOCK_PATTERN = re.compile(r"```(?:json)?\s*(\{.*\})\s*```", re.DOTALL)


def parse_json_payload(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if not stripped:
        raise ValueError("LLM returned empty content")

    try:
        payload = json.loads(stripped)
        if isinstance(payload, dict):
            return payload
        raise ValueError("Expected JSON object")
    except json.JSONDecodeError:
        pass

    fenced = _JSON_BLOCK_PATTERN.search(stripped)
    if fenced:
        payload = json.loads(fenced.group(1))
        if isinstance(payload, dict):
            return payload

    start = stripped.find("{")
    end = stripped.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("No JSON object found in LLM output")

    payload = json.loads(stripped[start : end + 1])
    if not isinstance(payload, dict):
        raise ValueError("Expected JSON object")
    return payload


class LLMClient:
    def __init__(
        self,
        *,
        model: str,
        temperature: float,
        max_tokens: int,
        max_retries: int,
        strict_json: bool = True,
        api_key: str | None = None,
    ) -> None:
        if OpenAI is None:
            raise RuntimeError(
                "openai package is not installed. Install dependencies with `pip install -e .`."
            )
        resolved_api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not resolved_api_key:
            raise RuntimeError(
                "OPENAI_API_KEY is not set. Export it in your environment before running."
            )
        self._client = OpenAI(api_key=resolved_api_key)
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.max_retries = max_retries
        self.strict_json = strict_json

    def ask_json(self, *, prompt: str, system: str = "You are a secure code analysis assistant.") -> dict[str, Any]:
        last_error: Exception | None = None
        for _ in range(self.max_retries + 1):
            try:
                req: dict[str, Any] = {
                    "model": self.model,
                    "temperature": self.temperature,
                    "max_tokens": self.max_tokens,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": prompt},
                    ],
                }
                if self.strict_json:
                    req["response_format"] = {"type": "json_object"}
                resp = self._client.chat.completions.create(**req)
                content = resp.choices[0].message.content or ""
                return parse_json_payload(content)
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                continue
        raise RuntimeError(f"LLM JSON call failed after retries: {last_error}")
