"""Thin async wrapper around Ollama's HTTP API for all LLM-dependent features."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

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
    """Async LLM client talking to a local Ollama server.

    When ``collect_training_data=True`` (or ``LLM_COLLECT_DATA=1`` env var),
    every request/response pair is appended as JSONL to a file for future
    fine-tuning. File defaults to ``shared/logs/llm_training.jsonl``.
    """

    def __init__(
        self,
        base_url: str | None = None,
        model: str | None = None,
        timeout: float | None = None,
        collect_training_data: bool | None = None,
        training_data_path: str | None = None,
    ):
        self._base_url = base_url or os.environ.get("LLM_BASE_URL", DEFAULT_BASE_URL)
        self._model = model or os.environ.get("LLM_MODEL", DEFAULT_MODEL)
        self._timeout = timeout or float(os.environ.get("LLM_TIMEOUT", str(DEFAULT_TIMEOUT)))
        self._collect = collect_training_data if collect_training_data is not None else (
            os.environ.get("LLM_COLLECT_DATA", "0") == "1"
        )
        self._data_path = Path(
            training_data_path or os.environ.get("LLM_TRAINING_DATA_PATH", "shared/logs/llm_training.jsonl")
        )

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

        result = LLMResponse(
            text=data.get("response", ""),
            input_tokens=int(data.get("prompt_eval_count", 0)),
            output_tokens=int(data.get("eval_count", 0)),
        )

        if self._collect:
            self._save_training_sample(system, prompt, result)

        return result

    def _save_training_sample(self, system: str | None, prompt: str, response: LLMResponse) -> None:
        """Append a request/response pair as JSONL for fine-tuning."""
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "model": self._model,
            "system": system,
            "prompt": prompt,
            "response": response.text,
            "input_tokens": response.input_tokens,
            "output_tokens": response.output_tokens,
        }
        self._data_path.parent.mkdir(parents=True, exist_ok=True)
        with self._data_path.open("a") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
