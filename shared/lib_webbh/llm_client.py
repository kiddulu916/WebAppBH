"""Thin async wrapper around Ollama's HTTP API for all LLM-dependent features."""
from __future__ import annotations

import os
from dataclasses import dataclass

import httpx


@dataclass
class LLMResponse:
    """Normalized response from the LLM."""
    text: str
    input_tokens: int
    output_tokens: int


# Defaults — overridable per-call or via env vars.
DEFAULT_BASE_URL = os.environ.get("LLM_BASE_URL", "http://ollama:11434")
DEFAULT_MODEL = os.environ.get("LLM_MODEL", "qwen3:14b")
DEFAULT_MAX_TOKENS = int(os.environ.get("LLM_MAX_TOKENS", "4096"))
DEFAULT_TIMEOUT = float(os.environ.get("LLM_TIMEOUT", "600.0"))


class LLMClient:
    """Async LLM client talking to a local Ollama server."""

    def __init__(
        self,
        base_url: str | None = None,
        model: str | None = None,
        timeout: float | None = None,
    ):
        self._base_url = base_url or os.environ.get("LLM_BASE_URL", DEFAULT_BASE_URL)
        self._model = model or os.environ.get("LLM_MODEL", DEFAULT_MODEL)
        self._timeout = timeout or float(os.environ.get("LLM_TIMEOUT", str(DEFAULT_TIMEOUT)))

    async def generate(
        self,
        prompt: str,
        system: str | None = None,
        max_tokens: int | None = None,
        temperature: float = 0.3,
        json_mode: bool = False,
    ) -> LLMResponse:
        """Send a single prompt to Ollama and return the response text + token counts."""
        body: dict = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens or DEFAULT_MAX_TOKENS,
            },
        }
        if system:
            body["system"] = system
        if json_mode:
            body["format"] = "json"

        async with httpx.AsyncClient(timeout=self._timeout) as http:
            response = await http.post(f"{self._base_url}/api/generate", json=body)
            response.raise_for_status()
            data = response.json()

        return LLMResponse(
            text=data.get("response", ""),
            input_tokens=int(data.get("prompt_eval_count", 0)),
            output_tokens=int(data.get("eval_count", 0)),
        )
