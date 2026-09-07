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
from app.services.mock_llm import mock_llm_service


class ProxyService:
    async def process_direct_chat(self, request: ChatCompletionRequest) -> Dict[str, Any]:
        """Send a request to the same LLM without firewall inspection.

        This endpoint is deliberately limited to the controlled demonstration
        environment and provides the baseline for firewall-on/off comparisons.
        """
        llm_response, _ = await self._forward_to_llm(request.model_dump())
        if isinstance(llm_response, dict):
            llm_response["promptguard_meta"] = {
                "firewall_applied": False,
                "mode": "DIRECT",
            }
        return llm_response

    async def process_chat_completion(
        self,
        request: ChatCompletionRequest,
        client_ip: str,
    ) -> Dict[str, Any]:
        start_time = time.time()
        request_id = f"req-{uuid.uuid4().hex[:12]}"
        user_id = request.user or "employee-default"

        # Inspect each message independently so detection offsets always refer
        # to the exact message being redacted.
        target_payload = request.model_dump()
        all_threats = []
        reasons = []
        redacted_prompt_parts = []
        blocked_stage = None

        for original, target in zip(request.messages, target_payload["messages"]):
            message_text = original.text_content()
            pipeline_result = detection_pipeline.run(message_text)
            decision = policy_engine.evaluate(message_text, pipeline_result)
            all_threats.extend(decision.detected_threats)
            reasons.extend(decision.reasons)
            redacted_prompt_parts.append(f"{original.role}: {decision.redacted_prompt}")

            if decision.action == PolicyAction.BLOCK and blocked_stage is None:
                blocked_stage = decision.blocked_by_stage
            elif decision.action == PolicyAction.REDACT:
                if isinstance(target["content"], list):
                    target["content"] = [{"type": "text", "text": decision.redacted_prompt}]
                else:
                    target["content"] = decision.redacted_prompt

        combined_prompt = "\n".join(
            f"{message.role}: {message.text_content()}" for message in request.messages
        )
        combined_redacted_prompt = "\n".join(redacted_prompt_parts)

        if blocked_stage is not None:
            decision = PolicyDecision(
                action=PolicyAction.BLOCK,
                original_prompt=combined_prompt,
                redacted_prompt="[REQUEST BLOCKED BY PROMPTGUARD FIREWALL]",
                reasons=reasons,
                detected_threats=all_threats,
                blocked_by_stage=blocked_stage,
            )
        elif all_threats:
            decision = PolicyDecision(
                action=PolicyAction.REDACT,
                original_prompt=combined_prompt,
                redacted_prompt=combined_redacted_prompt,
                reasons=reasons,
                detected_threats=all_threats,
            )
        else:
            decision = PolicyDecision(
                action=PolicyAction.ALLOW,
                original_prompt=combined_prompt,
                redacted_prompt=combined_prompt,
                reasons=["No security threats or sensitive data detected."],
                detected_threats=[],
            )

        if decision.action == PolicyAction.BLOCK:
            latency_ms = (time.time() - start_time) * 1000
            audit_logger.log_request(
                request_id=request_id,
                client_ip=client_ip,
                user_id=user_id,
                original_prompt=combined_prompt,
                decision=decision,
                status_code=403,
                latency_ms=latency_ms,
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
                            "severity": d.severity,
                        }
                        for d in decision.detected_threats
                    ],
                },
            )

        llm_response, status_code = await self._forward_to_llm(target_payload)
        latency_ms = (time.time() - start_time) * 1000

        if isinstance(llm_response, dict):
            llm_response["promptguard_meta"] = {
                "request_id": request_id,
                "action": decision.action.value,
                "redacted": decision.action == PolicyAction.REDACT,
                "detections_found": len(decision.detected_threats),
                "latency_ms": round(latency_ms, 2),
                "firewall_applied": True,
                "mode": "PROTECTED",
                "classification": decision.highest_classification.value,
            }

        audit_logger.log_request(
            request_id=request_id,
            client_ip=client_ip,
            user_id=user_id,
            original_prompt=combined_prompt,
            decision=decision,
            status_code=status_code,
            latency_ms=latency_ms,
        )
        return llm_response

    async def _forward_to_llm(self, payload: Dict[str, Any]) -> Tuple[Dict[str, Any], int]:
        """Forward payload to an upstream LLM API or the controlled mock LLM."""
        if settings.MOCK_LLM_MODE or not settings.OPENAI_API_KEY:
            return await mock_llm_service.chat_completion(payload), 200

        headers = {
            "Authorization": f"Bearer {settings.OPENAI_API_KEY}",
            "Content-Type": "application/json",
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.post(
                    settings.UPSTREAM_LLM_URL, json=payload, headers=headers
                )
                return response.json(), response.status_code
            except httpx.HTTPError:
                return {"error": "Upstream LLM connection failed."}, 502


proxy_service = ProxyService()
