"""Tests for the local LLM client wrapper (Ollama backend)."""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

pytestmark = pytest.mark.anyio


async def test_generate_text_returns_response():
    """LLMClient.generate() returns the text + token counts from Ollama."""
    mock_payload = {
        "response": "Hello world",
        "prompt_eval_count": 10,
        "eval_count": 5,
        "done": True,
    }
    mock_http_response = MagicMock()
    mock_http_response.json = MagicMock(return_value=mock_payload)
    mock_http_response.raise_for_status = MagicMock()

    with patch("lib_webbh.llm_client.httpx.AsyncClient") as MockClient:
        instance = MockClient.return_value.__aenter__.return_value
        instance.post = AsyncMock(return_value=mock_http_response)

        from lib_webbh.llm_client import LLMClient
        client = LLMClient(base_url="http://ollama:11434", model="qwen3:14b")
        result = await client.generate("Say hello")

        assert result.text == "Hello world"
        assert result.input_tokens == 10
        assert result.output_tokens == 5


async def test_generate_with_system_prompt():
    """System prompt is passed through to Ollama."""
    mock_payload = {"response": "ok", "prompt_eval_count": 5, "eval_count": 2, "done": True}
    mock_http_response = MagicMock()
    mock_http_response.json = MagicMock(return_value=mock_payload)
    mock_http_response.raise_for_status = MagicMock()

    with patch("lib_webbh.llm_client.httpx.AsyncClient") as MockClient:
        instance = MockClient.return_value.__aenter__.return_value
        instance.post = AsyncMock(return_value=mock_http_response)

        from lib_webbh.llm_client import LLMClient
        client = LLMClient()
        await client.generate("Analyze this vuln", system="You are a security analyst.")

        call_kwargs = instance.post.call_args
        body = call_kwargs.kwargs["json"]
        assert body["system"] == "You are a security analyst."


async def test_generate_json_mode():
    """JSON mode sets format=json in the Ollama request."""
    mock_payload = {"response": '{"ok": true}', "prompt_eval_count": 5, "eval_count": 2, "done": True}
    mock_http_response = MagicMock()
    mock_http_response.json = MagicMock(return_value=mock_payload)
    mock_http_response.raise_for_status = MagicMock()

    with patch("lib_webbh.llm_client.httpx.AsyncClient") as MockClient:
        instance = MockClient.return_value.__aenter__.return_value
        instance.post = AsyncMock(return_value=mock_http_response)

        from lib_webbh.llm_client import LLMClient
        client = LLMClient()
        result = await client.generate("Produce JSON", json_mode=True)

        body = instance.post.call_args.kwargs["json"]
        assert body["format"] == "json"
        assert result.text == '{"ok": true}'


async def test_client_uses_env_base_url_and_model():
    """Env vars override defaults: LLM_BASE_URL, LLM_MODEL."""
    with patch.dict("os.environ", {"LLM_BASE_URL": "http://custom:1234", "LLM_MODEL": "qwen3:8b"}):
        from lib_webbh.llm_client import LLMClient
        client = LLMClient()
        assert client._base_url == "http://custom:1234"
        assert client._model == "qwen3:8b"
