"""Deterministic OpenAI-compatible mock LLM for controlled security demonstrations."""

import time
import uuid
from typing import Any, Dict


class MockLLMService:
    """A safe, local stand-in for an upstream chat-completions provider."""

    _SENSITIVE_MARKERS = (
        "api_key",
        "password",
        "secret",
        "customer database",
        "protected information",
        "confidential",
    )

    async def chat_completion(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        messages = payload.get("messages", [])
        def content_text(message: Dict[str, Any]) -> str:
            content = message.get("content", "")
            if isinstance(content, list):
                return "\n".join(block.get("text", "") for block in content if block.get("type") == "text")
            return str(content)

        received_text = "\n".join(f"{message.get('role', 'user')}: {content_text(message)}" for message in messages)
        normalized = received_text.casefold()

        if any(marker in normalized for marker in self._SENSITIVE_MARKERS):
            content = (
                "The mock LLM received sensitive-looking content. "
                "For this controlled demo it returns only the synthetic canary "
                "DEMO_CANARY_FIREWALL_OFF and never exposes real data."
            )
        else:
            content = "Mock LLM processed the request successfully."

        return {
            "id": f"chatcmpl-{uuid.uuid4().hex[:10]}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": f"{payload.get('model', 'mock-model')}-mock",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }],
            "usage": {
                "prompt_tokens": max(1, len(received_text.split())),
                "completion_tokens": len(content.split()),
                "total_tokens": max(1, len(received_text.split())) + len(content.split()),
            },
            # This field is intentionally demo-only: it makes the firewall's
            # transformation visible without needing a real upstream provider.
            "mock_llm_meta": {
                "received_messages": messages,
                "received_prompt": received_text,
                "deterministic": True,
            },
        }


mock_llm_service = MockLLMService()
