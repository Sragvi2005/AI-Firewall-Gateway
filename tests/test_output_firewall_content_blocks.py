from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.services.mock_llm import mock_llm_service

client = TestClient(app)


def test_output_firewall_blocks_sensitive_text_inside_content_blocks(monkeypatch):
    original_gliner = settings.ENABLE_GLINER
    try:
        settings.ENABLE_GLINER = False

        async def mock_leaky_chat(payload):
            return {
                "id": "chatcmpl-content-block-leak",
                "object": "chat.completion",
                "created": 123456789,
                "model": "mock-model",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": [
                            {"type": "text", "text": "Safe introduction."},
                            {"type": "text", "text": "Leaked key: AKIAIOSFODNN7EXAMPLE"},
                        ],
                    },
                    "finish_reason": "stop",
                }],
            }

        monkeypatch.setattr(mock_llm_service, "chat_completion", mock_leaky_chat)

        response = client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": "Give me a safe summary."}],
            },
        )

        assert response.status_code == 200
        body = response.json()
        assert body["promptguard_meta"]["output_action"] == "BLOCK"
        assert body["promptguard_meta"]["output_detections_found"] >= 1
        assert body["choices"][0]["finish_reason"] == "content_filter"
        assert isinstance(body["choices"][0]["message"]["content"], str)
        assert "[RESPONSE BLOCKED BY PROMPTGUARD OUTPUT FIREWALL" in body["choices"][0]["message"]["content"]
    finally:
        settings.ENABLE_GLINER = original_gliner
