from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List

from app.models import PolicyAction, PolicyDecision


BLOCKED_RESPONSE_TEXT = (
    "[RESPONSE BLOCKED BY PROMPTGUARD OUTPUT FIREWALL: "
    "Sensitive data or policy violation detected in LLM response]"
)


@dataclass
class PayloadInspection:
    inspected: bool
    action: PolicyAction
    payload: Dict[str, Any]
    decisions: List[PolicyDecision] = field(default_factory=list)


def _action_rank(action: PolicyAction) -> int:
    return {PolicyAction.ALLOW: 0, PolicyAction.REDACT: 1, PolicyAction.BLOCK: 2}[action]


def _content_blocks(content: Any) -> List[Dict[str, Any]]:
    if not isinstance(content, list):
        return []
    return [
        block
        for block in content
        if isinstance(block, dict)
        and block.get("type") == "text"
        and isinstance(block.get("text"), str)
    ]


def inspect_chat_payload(
    payload: Dict[str, Any],
    inspect_text: Callable[[str], PolicyDecision],
) -> PayloadInspection:
    """Inspect OpenAI/Anthropic-style JSON payloads and redact text on a copy."""
    messages = payload.get("messages")
    has_prompt = isinstance(payload.get("prompt"), str)
    if not isinstance(messages, list) and not has_prompt:
        return PayloadInspection(False, PolicyAction.ALLOW, payload)

    sanitized = deepcopy(payload)
    decisions: List[PolicyDecision] = []
    final_action = PolicyAction.ALLOW

    if isinstance(messages, list):
        for message in sanitized["messages"]:
            if not isinstance(message, dict):
                continue
            content = message.get("content")
            if isinstance(content, str):
                decision = inspect_text(content)
                decisions.append(decision)
                if _action_rank(decision.action) > _action_rank(final_action):
                    final_action = decision.action
                if decision.action == PolicyAction.REDACT:
                    message["content"] = decision.redacted_prompt
                elif decision.action == PolicyAction.BLOCK:
                    return PayloadInspection(True, PolicyAction.BLOCK, sanitized, decisions)
            else:
                for block in _content_blocks(content):
                    decision = inspect_text(block["text"])
                    decisions.append(decision)
                    if _action_rank(decision.action) > _action_rank(final_action):
                        final_action = decision.action
                    if decision.action == PolicyAction.REDACT:
                        block["text"] = decision.redacted_prompt
                    elif decision.action == PolicyAction.BLOCK:
                        return PayloadInspection(True, PolicyAction.BLOCK, sanitized, decisions)

    if has_prompt:
        decision = inspect_text(sanitized["prompt"])
        decisions.append(decision)
        if _action_rank(decision.action) > _action_rank(final_action):
            final_action = decision.action
        if decision.action == PolicyAction.REDACT:
            sanitized["prompt"] = decision.redacted_prompt
        elif decision.action == PolicyAction.BLOCK:
            return PayloadInspection(True, PolicyAction.BLOCK, sanitized, decisions)

    return PayloadInspection(True, final_action, sanitized, decisions)


def _inspect_output_content(
    content: Any,
    inspect_text: Callable[[str], PolicyDecision],
) -> tuple[Any, PolicyAction, List[PolicyDecision]]:
    if isinstance(content, str):
        decision = inspect_text(content)
        if decision.action == PolicyAction.BLOCK:
            return BLOCKED_RESPONSE_TEXT, PolicyAction.BLOCK, [decision]
        if decision.action == PolicyAction.REDACT:
            return decision.redacted_prompt, PolicyAction.REDACT, [decision]
        return content, PolicyAction.ALLOW, [decision]

    if isinstance(content, list):
        updated = deepcopy(content)
        final_action = PolicyAction.ALLOW
        decisions: List[PolicyDecision] = []
        for block in updated:
            if not isinstance(block, dict) or block.get("type") != "text" or not isinstance(block.get("text"), str):
                continue
            sanitized, action, block_decisions = _inspect_output_content(block["text"], inspect_text)
            decisions.extend(block_decisions)
            if _action_rank(action) > _action_rank(final_action):
                final_action = action
            block["text"] = sanitized
            if action == PolicyAction.BLOCK:
                return BLOCKED_RESPONSE_TEXT, PolicyAction.BLOCK, decisions
        return updated, final_action, decisions

    return content, PolicyAction.ALLOW, []


def inspect_llm_response(
    payload: Dict[str, Any],
    inspect_text: Callable[[str], PolicyDecision],
) -> tuple[Dict[str, Any], PolicyAction, List[PolicyDecision]]:
    """Inspect common non-streaming chat-completion response shapes."""
    updated = deepcopy(payload)
    choices = updated.get("choices")
    if not isinstance(choices, list):
        return updated, PolicyAction.ALLOW, []

    final_action = PolicyAction.ALLOW
    decisions: List[PolicyDecision] = []

    for choice in choices:
        if not isinstance(choice, dict):
            continue
        message = choice.get("message")
        if isinstance(message, dict) and "content" in message:
            sanitized, action, found = _inspect_output_content(message["content"], inspect_text)
            decisions.extend(found)
            if _action_rank(action) > _action_rank(final_action):
                final_action = action
            message["content"] = sanitized
            if action == PolicyAction.BLOCK:
                choice["finish_reason"] = "content_filter"
                return updated, PolicyAction.BLOCK, decisions

    return updated, final_action, decisions


def inspect_sse_response(
    body: str,
    inspect_text: Callable[[str], PolicyDecision],
) -> tuple[str, PolicyAction, List[PolicyDecision]]:
    """Inspect OpenAI-style SSE after mitmproxy has buffered the response.

    When content is unsafe, emit a compact safe stream containing one sanitized
    assistant delta and a final [DONE]. This prevents sensitive output from being
    released even when the upstream client requested stream=true.
    """
    events: List[Dict[str, Any]] = []
    raw_events: List[str] = []
    cumulative: Dict[int, str] = {}

    for raw_event in body.split("\n\n"):
        stripped = raw_event.strip("\r\n")
        if not stripped:
            continue
        data_lines = [line[5:].lstrip() for line in stripped.splitlines() if line.startswith("data:")]
        if not data_lines:
            raw_events.append(raw_event)
            continue
        data = "\n".join(data_lines)
        if data == "[DONE]":
            raw_events.append(raw_event)
            continue
        try:
            event = json.loads(data)
        except json.JSONDecodeError:
            return body, PolicyAction.ALLOW, []
        if not isinstance(event, dict):
            return body, PolicyAction.ALLOW, []
        events.append(event)
        raw_events.append(raw_event)
        for choice in event.get("choices", []):
            if not isinstance(choice, dict):
                continue
            index = choice.get("index", 0)
            delta = choice.get("delta")
            if isinstance(delta, dict) and isinstance(delta.get("content"), str):
                cumulative[index] = cumulative.get(index, "") + delta["content"]

    if not cumulative:
        return body, PolicyAction.ALLOW, []

    decisions: List[PolicyDecision] = []
    final_action = PolicyAction.ALLOW
    sanitized_by_index: Dict[int, str] = {}
    for index, text in cumulative.items():
        decision = inspect_text(text)
        decisions.append(decision)
        if _action_rank(decision.action) > _action_rank(final_action):
            final_action = decision.action
        sanitized_by_index[index] = (
            BLOCKED_RESPONSE_TEXT
            if decision.action == PolicyAction.BLOCK
            else decision.redacted_prompt
            if decision.action == PolicyAction.REDACT
            else text
        )

    if final_action == PolicyAction.ALLOW:
        return body, final_action, decisions

    chunks: List[str] = []
    for index in sorted(sanitized_by_index):
        finish_reason = "content_filter" if final_action == PolicyAction.BLOCK else None
        delta_payload: Dict[str, Any] = {"role": "assistant", "content": sanitized_by_index[index]}
        choice: Dict[str, Any] = {"index": index, "delta": delta_payload}
        if finish_reason:
            choice["finish_reason"] = finish_reason
        event = {"choices": [choice]}
        chunks.append(f"data: {json.dumps(event, ensure_ascii=False)}\n\n")
    chunks.append("data: [DONE]\n\n")
    return "".join(chunks), final_action, decisions
