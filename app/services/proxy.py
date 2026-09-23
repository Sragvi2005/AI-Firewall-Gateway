import time
import uuid
import httpx
from typing import Dict, Any, Tuple, Optional
from fastapi import HTTPException
from app.config import settings, LLMProvider, PROVIDER_DEFAULT_MODELS
from app.models import ChatCompletionRequest, PolicyAction, PolicyDecision
from app.detectors.pipeline import detection_pipeline
from app.policy.engine import policy_engine
from app.compliance.audit import audit_logger


def _resolve_provider(request_provider: Optional[str]) -> LLMProvider:
    """Resolve the LLM provider from the request or fall back to the server default."""
    if request_provider:
        try:
            return LLMProvider(request_provider.lower())
        except ValueError:
            pass
    return settings.LLM_PROVIDER


def _resolve_model(model: str, provider: LLMProvider) -> str:
    """Resolve the model name — use the request model if provided, otherwise the provider default."""
    if model:
        return model
    return PROVIDER_DEFAULT_MODELS.get(provider, "default")


# ─────────────────────────────────────────────────────────────
#  Provider Adapters
#  Each adapter transforms the OpenAI-style payload to the
#  provider's native format, makes the HTTP call, and normalizes
#  the response back to OpenAI format.
# ─────────────────────────────────────────────────────────────

async def _forward_openai_compatible(
    payload: Dict[str, Any],
    provider: LLMProvider,
) -> Tuple[Dict[str, Any], int]:
    """
    Forward to any OpenAI-compatible API (OpenAI, Groq, Mistral, Custom).
    These all use the same request/response schema and Bearer auth.
    """
    url = settings.get_upstream_url(provider)
    api_key = settings.get_api_key(provider)

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    # Strip non-standard fields before sending
    send_payload = {k: v for k, v in payload.items() if k not in ("provider", "user")}

    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            resp = await client.post(url, json=send_payload, headers=headers)
            return resp.json(), resp.status_code
        except Exception as e:
            return {"error": f"Upstream LLM Connection Failed ({provider.value}): {str(e)}"}, 502


async def _forward_anthropic(
    payload: Dict[str, Any],
    provider: LLMProvider,
) -> Tuple[Dict[str, Any], int]:
    """
    Transform to Anthropic Messages API format and normalize response back.
    Anthropic uses x-api-key header, anthropic-version, and a different body schema.
    """
    url = settings.get_upstream_url(provider)
    api_key = settings.get_api_key(provider)
    model = payload.get("model", "claude-sonnet-4-20250514")

    # Transform messages: Anthropic expects {role, content} but no "system" in messages array.
    # System messages go into a top-level "system" field.
    messages = payload.get("messages", [])
    system_parts = []
    anthropic_messages = []
    for msg in messages:
        if msg.get("role") == "system":
            system_parts.append(msg.get("content", ""))
        else:
            anthropic_messages.append({
                "role": msg.get("role", "user"),
                "content": msg.get("content", ""),
            })

    anthropic_payload = {
        "model": model,
        "messages": anthropic_messages,
        "max_tokens": payload.get("max_tokens", 1024),
    }
    if payload.get("temperature") is not None:
        anthropic_payload["temperature"] = payload["temperature"]
    if system_parts:
        anthropic_payload["system"] = "\n".join(system_parts)

    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
    }

    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            resp = await client.post(url, json=anthropic_payload, headers=headers)
            data = resp.json()

            if resp.status_code != 200:
                return {"error": f"Anthropic API error: {data}"}, resp.status_code

            # Normalize Anthropic response to OpenAI format
            content_blocks = data.get("content", [])
            text_content = ""
            for block in content_blocks:
                if isinstance(block, dict) and block.get("type") == "text":
                    text_content += block.get("text", "")
                elif isinstance(block, str):
                    text_content += block

            normalized = {
                "id": data.get("id", f"chatcmpl-{uuid.uuid4().hex[:10]}"),
                "object": "chat.completion",
                "created": int(time.time()),
                "model": data.get("model", model),
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": text_content,
                    },
                    "finish_reason": _map_anthropic_stop(data.get("stop_reason", "end_turn")),
                }],
                "usage": {
                    "prompt_tokens": data.get("usage", {}).get("input_tokens", 0),
                    "completion_tokens": data.get("usage", {}).get("output_tokens", 0),
                    "total_tokens": (
                        data.get("usage", {}).get("input_tokens", 0)
                        + data.get("usage", {}).get("output_tokens", 0)
                    ),
                },
            }
            return normalized, 200

        except Exception as e:
            return {"error": f"Anthropic Connection Failed: {str(e)}"}, 502


def _map_anthropic_stop(stop_reason: str) -> str:
    mapping = {
        "end_turn": "stop",
        "max_tokens": "length",
        "stop_sequence": "stop",
    }
    return mapping.get(stop_reason, "stop")


async def _forward_gemini(
    payload: Dict[str, Any],
    provider: LLMProvider,
) -> Tuple[Dict[str, Any], int]:
    """
    Transform to Google Gemini REST API format and normalize response back.
    Gemini uses API key as query param and a completely different body schema.
    """
    api_key = settings.get_api_key(provider)
    base_url = settings.get_upstream_url(provider)
    model = payload.get("model", "gemini-2.0-flash")

    url = f"{base_url}/models/{model}:generateContent?key={api_key}"

    # Transform messages to Gemini format
    messages = payload.get("messages", [])
    gemini_contents = []
    system_instruction = None

    for msg in messages:
        role = msg.get("role", "user")
        content = msg.get("content", "")

        if role == "system":
            system_instruction = content
            continue

        # Gemini uses "user" and "model" roles
        gemini_role = "model" if role == "assistant" else "user"
        gemini_contents.append({
            "role": gemini_role,
            "parts": [{"text": content}],
        })

    gemini_payload = {
        "contents": gemini_contents,
    }

    if system_instruction:
        gemini_payload["systemInstruction"] = {
            "parts": [{"text": system_instruction}]
        }

    # Map generation config
    generation_config = {}
    if payload.get("temperature") is not None:
        generation_config["temperature"] = payload["temperature"]
    if payload.get("max_tokens"):
        generation_config["maxOutputTokens"] = payload["max_tokens"]
    if generation_config:
        gemini_payload["generationConfig"] = generation_config

    headers = {"Content-Type": "application/json"}

    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            resp = await client.post(url, json=gemini_payload, headers=headers)
            data = resp.json()

            if resp.status_code != 200:
                return {"error": f"Gemini API error: {data}"}, resp.status_code

            # Normalize Gemini response to OpenAI format
            candidates = data.get("candidates", [])
            text_content = ""
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                for part in parts:
                    text_content += part.get("text", "")

            usage_meta = data.get("usageMetadata", {})
            normalized = {
                "id": f"chatcmpl-{uuid.uuid4().hex[:10]}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": model,
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": text_content,
                    },
                    "finish_reason": "stop",
                }],
                "usage": {
                    "prompt_tokens": usage_meta.get("promptTokenCount", 0),
                    "completion_tokens": usage_meta.get("candidatesTokenCount", 0),
                    "total_tokens": usage_meta.get("totalTokenCount", 0),
                },
            }
            return normalized, 200

        except Exception as e:
            return {"error": f"Gemini Connection Failed: {str(e)}"}, 502


async def _forward_cohere(
    payload: Dict[str, Any],
    provider: LLMProvider,
) -> Tuple[Dict[str, Any], int]:
    """
    Transform to Cohere Chat API v2 format and normalize response back.
    Cohere uses Bearer auth with a different request/response schema.
    """
    url = settings.get_upstream_url(provider)
    api_key = settings.get_api_key(provider)
    model = payload.get("model", "command-r-plus")

    # Transform messages to Cohere format
    messages = payload.get("messages", [])
    cohere_messages = []
    for msg in messages:
        role = msg.get("role", "user")
        content = msg.get("content", "")
        # Cohere v2 uses "user", "assistant", "system" — same as OpenAI
        cohere_messages.append({
            "role": role,
            "content": content,
        })

    cohere_payload = {
        "model": model,
        "messages": cohere_messages,
    }

    if payload.get("temperature") is not None:
        cohere_payload["temperature"] = payload["temperature"]
    if payload.get("max_tokens"):
        cohere_payload["max_tokens"] = payload["max_tokens"]

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            resp = await client.post(url, json=cohere_payload, headers=headers)
            data = resp.json()

            if resp.status_code != 200:
                return {"error": f"Cohere API error: {data}"}, resp.status_code

            # Normalize Cohere response to OpenAI format
            # Cohere v2 response has message.content[].text
            assistant_msg = data.get("message", {})
            content_blocks = assistant_msg.get("content", [])
            text_content = ""
            for block in content_blocks:
                if isinstance(block, dict) and block.get("type") == "text":
                    text_content += block.get("text", "")
                elif isinstance(block, str):
                    text_content += block

            usage = data.get("usage", {})
            tokens = usage.get("tokens", {})
            normalized = {
                "id": data.get("id", f"chatcmpl-{uuid.uuid4().hex[:10]}"),
                "object": "chat.completion",
                "created": int(time.time()),
                "model": model,
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": text_content,
                    },
                    "finish_reason": _map_cohere_stop(data.get("finish_reason", "COMPLETE")),
                }],
                "usage": {
                    "prompt_tokens": tokens.get("input_tokens", 0),
                    "completion_tokens": tokens.get("output_tokens", 0),
                    "total_tokens": (
                        tokens.get("input_tokens", 0)
                        + tokens.get("output_tokens", 0)
                    ),
                },
            }
            return normalized, 200

        except Exception as e:
            return {"error": f"Cohere Connection Failed: {str(e)}"}, 502


def _map_cohere_stop(finish_reason: str) -> str:
    mapping = {
        "COMPLETE": "stop",
        "MAX_TOKENS": "length",
        "STOP_SEQUENCE": "stop",
    }
    return mapping.get(finish_reason, "stop")


# ─────────────────────────────────────────────────────────────
#  Provider Dispatcher
# ─────────────────────────────────────────────────────────────

# Map providers to their forwarding functions
PROVIDER_FORWARDERS = {
    LLMProvider.OPENAI: _forward_openai_compatible,
    LLMProvider.GROQ: _forward_openai_compatible,
    LLMProvider.MISTRAL: _forward_openai_compatible,
    LLMProvider.CUSTOM: _forward_openai_compatible,
    LLMProvider.ANTHROPIC: _forward_anthropic,
    LLMProvider.GEMINI: _forward_gemini,
    LLMProvider.COHERE: _forward_cohere,
}


class ProxyService:
    async def process_chat_completion(
        self,
        request: ChatCompletionRequest,
        client_ip: str
    ) -> Dict[str, Any]:
        start_time = time.time()
        request_id = f"req-{uuid.uuid4().hex[:12]}"
        user_id = request.user or "employee-default"

        # Resolve provider and model
        provider = _resolve_provider(request.provider)
        model = _resolve_model(request.model, provider)

        # 1. Extract combined prompt text from messages (handle multimodal content)
        prompt_parts = []
        for msg in request.messages:
            content = msg.content
            if isinstance(content, str):
                prompt_parts.append(f"{msg.role}: {content}")
            elif isinstance(content, list):
                text_parts = [
                    p.get("text", "") for p in content
                    if isinstance(p, dict) and p.get("type") == "text"
                ]
                prompt_parts.append(f"{msg.role}: {' '.join(text_parts)}")
            else:
                prompt_parts.append(f"{msg.role}: {str(content)}")
        combined_prompt = "\n".join(prompt_parts)

        # Collect all attachments for media scanning
        all_attachments = []
        for msg in request.messages:
            if msg.attachments:
                for att in msg.attachments:
                    all_attachments.append({
                        "filename": att.filename,
                        "content_base64": att.content_base64,
                        "mime_type": att.mime_type,
                    })
            # Also extract base64 images from multimodal content arrays
            if isinstance(msg.content, list):
                for part in msg.content:
                    if isinstance(part, dict) and part.get("type") == "image_url":
                        image_url = part.get("image_url", {})
                        url = image_url.get("url", "") if isinstance(image_url, dict) else str(image_url)
                        if url.startswith("data:"):
                            all_attachments.append({
                                "filename": "inline_image",
                                "content_base64": url,
                                "mime_type": "image/png",
                            })

        # 2. Run 4-stage detection pipeline (with media scanning)
        pipeline_result = detection_pipeline.run(
            combined_prompt,
            attachments=all_attachments if all_attachments else None
        )

        # 3. Evaluate Policy Decision
        decision: PolicyDecision = policy_engine.evaluate(combined_prompt, pipeline_result)

        # Handle Policy Outcomes
        if decision.action == PolicyAction.BLOCK:
            latency_ms = (time.time() - start_time) * 1000
            audit_logger.log_request(
                request_id=request_id,
                client_ip=client_ip,
                user_id=user_id,
                original_prompt=combined_prompt,
                decision=decision,
                status_code=403,
                latency_ms=latency_ms
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "PromptGuard Security Policy Violation",
                    "request_id": request_id,
                    "action": "BLOCK",
                    "blocked_by_stage": decision.blocked_by_stage,
                    "reasons": decision.reasons,
                    "violations": [
                        {
                            "stage": d.stage_name,
                            "type": d.entity_type,
                            "snippet": d.text_snippet,
                            "severity": d.severity
                        }
                        for d in decision.detected_threats
                    ]
                }
            )

        # Prepare modified payload if REDACT
        target_payload = request.model_dump()
        target_payload["model"] = model  # Ensure resolved model is used

        # Strip attachments from payload before forwarding to LLM
        for msg in target_payload.get("messages", []):
            msg.pop("attachments", None)

        if decision.action == PolicyAction.REDACT:
            # Update the last user message or all user messages with redacted prompt
            for msg in target_payload.get("messages", []):
                if msg.get("role") == "user":
                    content = msg.get("content", "")
                    if isinstance(content, str):
                        msg["content"] = policy_engine._apply_redaction(
                            content, pipeline_result.all_matches
                        )
                    elif isinstance(content, list):
                        for part in content:
                            if isinstance(part, dict) and part.get("type") == "text":
                                part["text"] = policy_engine._apply_redaction(
                                    part.get("text", ""), pipeline_result.all_matches
                                )

        # Forward request to LLM (Upstream or Mock)
        llm_response, status_code = await self._forward_to_llm(target_payload, provider)
        latency_ms = (time.time() - start_time) * 1000

        # Inject PromptGuard metadata into LLM response for audit transparency
        if isinstance(llm_response, dict):
            llm_response["promptguard_meta"] = {
                "request_id": request_id,
                "action": decision.action.value,
                "redacted": decision.action == PolicyAction.REDACT,
                "detections_found": len(decision.detected_threats),
                "provider": provider.value,
                "latency_ms": round(latency_ms, 2)
            }

        # Log transaction to Audit Log & DB
        audit_logger.log_request(
            request_id=request_id,
            client_ip=client_ip,
            user_id=user_id,
            original_prompt=combined_prompt,
            decision=decision,
            status_code=status_code,
            latency_ms=latency_ms
        )

        return llm_response

    async def _forward_to_llm(
        self,
        payload: Dict[str, Any],
        provider: LLMProvider | None = None,
    ) -> Tuple[Dict[str, Any], int]:
        """Forward payload to the appropriate upstream LLM API or return mock response."""
        resolved_provider = provider or _resolve_provider(payload.get("provider"))

        if settings.MOCK_LLM_MODE or not settings.get_api_key(resolved_provider):
            # Return realistic OpenAI Chat Completion format (provider-agnostic mock)
            model_name = payload.get("model", settings.get_default_model(resolved_provider))
            mock_response = {
                "id": f"chatcmpl-{uuid.uuid4().hex[:10]}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": f"{model_name}-promptguard-secured",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": (
                                "Hello! I am your AI Assistant behind PromptGuard Gateway. "
                                "Your prompt was analyzed, sanitized, and safely processed. "
                                f"[Provider: {resolved_provider.value} | Model: {model_name}]"
                            )
                        },
                        "finish_reason": "stop"
                    }
                ],
                "usage": {
                    "prompt_tokens": 30,
                    "completion_tokens": 25,
                    "total_tokens": 55
                }
            }
            return mock_response, 200

        # Dispatch to the appropriate provider adapter
        forwarder = PROVIDER_FORWARDERS.get(resolved_provider, _forward_openai_compatible)
        return await forwarder(payload, resolved_provider)


proxy_service = ProxyService()
