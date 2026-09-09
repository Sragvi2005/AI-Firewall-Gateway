"""Deterministic OpenAI-compatible mock LLM for controlled security demonstrations."""

import time
import uuid
from typing import Any, Dict, Optional


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

    async def chat_completion(
        self,
        payload: Dict[str, Any],
        scenario: Optional[str] = None,
    ) -> Dict[str, Any]:
        messages = payload.get("messages", [])

        def content_text(message: Dict[str, Any]) -> str:
            content = message.get("content", "")
            if isinstance(content, list):
                return "\n".join(
                    block.get("text", "")
                    for block in content
                    if isinstance(block, dict) and block.get("type") == "text"
                )
            return str(content)

        received_text = "\n".join(
            f"{message.get('role', 'user')}: {content_text(message)}" for message in messages
        )
        normalized = received_text.casefold()

        # These scenarios are local-only test fixtures used by /demo. They
        # deliberately return synthetic sensitive values so the output firewall
        # can be demonstrated without ever contacting a real provider.
        if scenario == "output-secret":
            content: Any = (
                "Deployment completed. The generated configuration contained "
                "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE."
            )
        elif scenario == "output-structured-secret":
            content = [
                {
                    "type": "text",
                    "text": "Deployment completed successfully.",
                },
                {
                    "type": "text",
                    "text": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
                },
            ]
        elif scenario == "output-pii":
            content = "The deployment owner is demo@example.test and the rollout is complete."
        elif any(marker in normalized for marker in self._SENSITIVE_MARKERS):
            content = (
                "The mock LLM received sensitive-looking content. "
                "For this controlled demo it returns only the synthetic canary "
                "DEMO_CANARY_FIREWALL_OFF and never exposes real data."
            )
        else:
            content = "Mock LLM processed the request successfully."

        completion_tokens = len(
            "\n".join(
                block.get("text", "")
                for block in content
                if isinstance(block, dict) and isinstance(block.get("text"), str)
            ).split()
        ) if isinstance(content, list) else len(str(content).split())

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
                "completion_tokens": completion_tokens,
                "total_tokens": max(1, len(received_text.split())) + completion_tokens,
            },
            # This field is intentionally demo-only: it makes the firewall's
            # transformation visible without needing a real upstream provider.
            "mock_llm_meta": {
                "received_messages": messages,
                "received_prompt": received_text,
                "deterministic": True,
                "scenario": scenario or "normal",
            },
        }


mock_llm_service = MockLLMService()
