from app.models import DataClassification, DetectionMatch, PolicyAction, PolicyDecision, ThreatSeverity
from app.proxy.transformer import BLOCKED_RESPONSE_TEXT, inspect_chat_payload, inspect_llm_response, inspect_sse_response


def decision_for(action: PolicyAction, original: str, redacted: str | None = None) -> PolicyDecision:
    match = DetectionMatch(
        stage_id=1,
        stage_name="Stage 1: PII",
        entity_type="EMAIL_ADDRESS",
        text_snippet="alice@example.com",
        start=0,
        end=min(len(original), 17),
        confidence=0.99,
        severity=ThreatSeverity.MEDIUM,
        description="Email detected",
    )
    return PolicyDecision(
        action=action,
        original_prompt=original,
        redacted_prompt=redacted or original,
        reasons=["test"],
        detected_threats=[match],
        classifications=[DataClassification.CONFIDENTIAL],
        highest_classification=DataClassification.CONFIDENTIAL,
    )


def test_request_redaction_preserves_unrelated_fields_and_content_blocks():
    payload = {
        "model": "gpt-test",
        "messages": [
            {"role": "system", "content": "system"},
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "alice@example.com"},
                    {"type": "image_url", "image_url": {"url": "https://example.com/image"}},
                ],
            },
        ],
    }

    def inspect(text: str):
        if text == "alice@example.com":
            return decision_for(PolicyAction.REDACT, text, "[EMAIL_ADDRESS]")
        return decision_for(PolicyAction.ALLOW, text)

    result = inspect_chat_payload(payload, inspect)

    assert result.inspected is True
    assert result.action == PolicyAction.REDACT
    assert result.payload["messages"][1]["content"][0]["text"] == "[EMAIL_ADDRESS]"
    assert result.payload["messages"][1]["content"][1]["type"] == "image_url"
    assert payload["messages"][1]["content"][0]["text"] == "alice@example.com"


def test_request_block_stops_forwarding_decision():
    payload = {"model": "gpt-test", "messages": [{"role": "user", "content": "attack"}]}

    result = inspect_chat_payload(
        payload,
        lambda text: decision_for(PolicyAction.BLOCK, text, "[REQUEST BLOCKED]")
    )

    assert result.inspected is True
    assert result.action == PolicyAction.BLOCK


def test_prompt_field_is_supported_for_non_chat_json_clients():
    payload = {"model": "custom", "prompt": "alice@example.com", "temperature": 0}
    result = inspect_chat_payload(
        payload,
        lambda text: decision_for(PolicyAction.REDACT, text, "[EMAIL_ADDRESS]")
    )

    assert result.action == PolicyAction.REDACT
    assert result.payload["prompt"] == "[EMAIL_ADDRESS]"


def test_output_firewall_blocks_chat_message_content():
    response = {
        "choices": [
            {"index": 0, "message": {"role": "assistant", "content": "secret"}, "finish_reason": "stop"}
        ]
    }

    sanitized, action, _ = inspect_llm_response(
        response,
        lambda text: decision_for(PolicyAction.BLOCK, text, "[BLOCKED]")
    )

    assert action == PolicyAction.BLOCK
    assert sanitized["choices"][0]["message"]["content"] == BLOCKED_RESPONSE_TEXT
    assert sanitized["choices"][0]["finish_reason"] == "content_filter"


def test_output_firewall_redacts_text_inside_content_blocks():
    response = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": [
                        {"type": "text", "text": "alice@example.com"},
                        {"type": "image_url", "image_url": {"url": "https://example.com/image"}},
                    ],
                }
            }
        ]
    }

    sanitized, action, _ = inspect_llm_response(
        response,
        lambda text: decision_for(PolicyAction.REDACT, text, "[EMAIL_ADDRESS]")
    )

    assert action == PolicyAction.REDACT
    assert sanitized["choices"][0]["message"]["content"][0]["text"] == "[EMAIL_ADDRESS]"
    assert sanitized["choices"][0]["message"]["content"][1]["type"] == "image_url"


def test_streaming_output_is_checked_as_a_whole():
    body = (
        'data: {"choices":[{"index":0,"delta":{"content":"alice@"}}]}\n\n'
        'data: {"choices":[{"index":0,"delta":{"content":"example.com"}}]}\n\n'
        'data: [DONE]\n\n'
    )

    sanitized, action, _ = inspect_sse_response(
        body,
        lambda text: decision_for(PolicyAction.REDACT, text, "[EMAIL_ADDRESS]")
        if "alice@example.com" in text
        else decision_for(PolicyAction.ALLOW, text),
    )

    assert action == PolicyAction.REDACT
    assert "[EMAIL_ADDRESS]" in sanitized
    assert "alice@example.com" not in sanitized
    assert sanitized.endswith("data: [DONE]\n\n")


def test_streaming_output_block_becomes_content_filter_event():
    body = 'data: {"choices":[{"index":0,"delta":{"content":"secret"}}]}\n\ndata: [DONE]\n\n'

    sanitized, action, _ = inspect_sse_response(
        body,
        lambda text: decision_for(PolicyAction.BLOCK, text, "[BLOCKED]"),
    )

    assert action == PolicyAction.BLOCK
    assert BLOCKED_RESPONSE_TEXT in sanitized
    assert '"finish_reason": "content_filter"' in sanitized
    assert sanitized.endswith("data: [DONE]\n\n")
