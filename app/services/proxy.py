import time
import uuid
import httpx
from typing import Dict, Any, Tuple
from fastapi import HTTPException
from app.config import settings
from app.models import ChatCompletionRequest, PolicyAction, PolicyDecision
from app.detectors.pipeline import detection_pipeline
from app.policy.engine import policy_engine
from app.compliance.audit import audit_logger

class ProxyService:
    async def process_chat_completion(
        self,
        request: ChatCompletionRequest,
        client_ip: str
    ) -> Dict[str, Any]:
        start_time = time.time()
        request_id = f"req-{uuid.uuid4().hex[:12]}"
        user_id = request.user or "employee-default"

        # 1. Extract combined prompt text from messages
        prompt_parts = []
        for msg in request.messages:
            prompt_parts.append(f"{msg.role}: {msg.content}")
        combined_prompt = "\n".join(prompt_parts)

        # 2. Run 4-stage detection pipeline
        pipeline_result = detection_pipeline.run(combined_prompt)

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
        if decision.action == PolicyAction.REDACT:
            # Update the last user message or all user messages with redacted prompt
            for msg in target_payload.get("messages", []):
                if msg.get("role") == "user":
                    # Simple single-user prompt redaction or inline redaction
                    redacted_user_text = policy_engine._apply_redaction(
                        msg["content"],
                        pipeline_result.all_matches
                    )
                    msg["content"] = redacted_user_text

        # Forward request to LLM (Upstream or Mock)
        llm_response, status_code = await self._forward_to_llm(target_payload)
        latency_ms = (time.time() - start_time) * 1000

        # Inject PromptGuard metadata into LLM response for audit transparency
        if isinstance(llm_response, dict):
            llm_response["promptguard_meta"] = {
                "request_id": request_id,
                "action": decision.action.value,
                "redacted": decision.action == PolicyAction.REDACT,
                "detections_found": len(decision.detected_threats),
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

    async def _forward_to_llm(self, payload: Dict[str, Any]) -> Tuple[Dict[str, Any], int]:
        """Forward payload to upstream LLM API or return mock response."""
        if settings.MOCK_LLM_MODE or not settings.OPENAI_API_KEY:
            # Return realistic OpenAI Chat Completion format
            mock_response = {
                "id": f"chatcmpl-{uuid.uuid4().hex[:10]}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": payload.get("model", "gpt-3.5-turbo") + "-promptguard-secured",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": (
                                "Hello! I am your AI Assistant behind PromptGuard Gateway. "
                                "Your prompt was analyzed, sanitized, and safely processed."
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

        # Live upstream HTTP request
        headers = {
            "Authorization": f"Bearer {settings.OPENAI_API_KEY}",
            "Content-Type": "application/json"
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                resp = await client.post(settings.UPSTREAM_LLM_URL, json=payload, headers=headers)
                return resp.json(), resp.status_code
            except Exception as e:
                return {"error": f"Upstream LLM Connection Failed: {str(e)}"}, 502

proxy_service = ProxyService()
