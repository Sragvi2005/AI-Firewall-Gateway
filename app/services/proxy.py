import time
import uuid
import httpx
from typing import Dict, Any, Tuple, Optional
from fastapi import HTTPException
from app.config import settings
from app.models import ChatCompletionRequest, PolicyAction, PolicyDecision, DataClassification
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
        if request.stream:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "Streaming is currently unsupported by PromptGuard Gateway. Set stream=False."
                },
            )
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
        demo_scenario: Optional[str] = None,
    ) -> Dict[str, Any]:
        if request.stream:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "Streaming is currently unsupported by PromptGuard Gateway. Set stream=False."
                },
            )
        start_time = time.time()
        request_id = f"req-{uuid.uuid4().hex[:12]}"
        user_id = request.user or "employee-default"

        # Inspect each message independently so detection offsets always refer
        # to the exact message being redacted.
        target_payload = request.model_dump()
        all_threats = []
        reasons = []
        all_classifications = set()
        redacted_prompt_parts = []
        blocked_stage = None

        for original, target in zip(request.messages, target_payload["messages"]):
            message_text = original.text_content()
            pipeline_result = detection_pipeline.run(message_text)
            decision = policy_engine.evaluate(message_text, pipeline_result)
            all_threats.extend(decision.detected_threats)
            reasons.extend(decision.reasons)
            all_classifications.update(decision.classifications)
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

        ordered_classifications = sorted(
            all_classifications,
            key=lambda c: {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3}.get(c.value, 0),
        )
        highest_classification = ordered_classifications[-1] if ordered_classifications else DataClassification.PUBLIC

        if blocked_stage is not None:
            decision = PolicyDecision(
                action=PolicyAction.BLOCK,
                original_prompt=combined_prompt,
                redacted_prompt="[REQUEST BLOCKED BY PROMPTGUARD FIREWALL]",
                reasons=reasons,
                detected_threats=all_threats,
                blocked_by_stage=blocked_stage,
                classifications=ordered_classifications,
                highest_classification=highest_classification,
            )
        elif all_threats:
            decision = PolicyDecision(
                action=PolicyAction.REDACT,
                original_prompt=combined_prompt,
                redacted_prompt=combined_redacted_prompt,
                reasons=reasons,
                detected_threats=all_threats,
                classifications=ordered_classifications,
                highest_classification=highest_classification,
            )
        else:
            decision = PolicyDecision(
                action=PolicyAction.ALLOW,
                original_prompt=combined_prompt,
                redacted_prompt=combined_prompt,
                reasons=["No security threats or sensitive data detected."],
                detected_threats=[],
                classifications=ordered_classifications,
                highest_classification=highest_classification,
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

        llm_response, status_code = await self._forward_to_llm(target_payload, demo_scenario=demo_scenario)
        latency_ms = (time.time() - start_time) * 1000

        # Output Firewall: inspect every textual assistant response before it is
        # returned to the caller. This supports both OpenAI-style string content
        # and content-block lists containing text blocks.
        output_action = PolicyAction.ALLOW
        output_detections_count = 0
        if settings.ENABLE_OUTPUT_FIREWALL and isinstance(llm_response, dict) and "choices" in llm_response:
            for choice in llm_response.get("choices", []):
                message = choice.get("message", {})
                content = message.get("content", "")

                if isinstance(content, str) and content:
                    updated_content, block_found, redaction_count = self._inspect_output_text(content)
                    message["content"] = updated_content
                    output_detections_count += redaction_count
                    if block_found:
                        output_action = PolicyAction.BLOCK
                        choice["finish_reason"] = "content_filter"
                    elif redaction_count and output_action != PolicyAction.BLOCK:
                        output_action = PolicyAction.REDACT

                elif isinstance(content, list):
                    for block in content:
                        if not isinstance(block, dict):
                            continue
                        block_text = block.get("text")
                        if not isinstance(block_text, str) or not block_text:
                            continue

                        updated_text, block_found, redaction_count = self._inspect_output_text(block_text)
                        block["text"] = updated_text
                        output_detections_count += redaction_count
                        if block_found:
                            output_action = PolicyAction.BLOCK
                            choice["finish_reason"] = "content_filter"
                        elif redaction_count and output_action != PolicyAction.BLOCK:
                            output_action = PolicyAction.REDACT

                    if output_action == PolicyAction.BLOCK:
                        message["content"] = "[RESPONSE BLOCKED BY PROMPTGUARD OUTPUT FIREWALL: Sensitive data or policy violation detected in LLM response]"

        if isinstance(llm_response, dict):
            llm_response["promptguard_meta"] = {
                "request_id": request_id,
                "action": decision.action.value,
                "redacted": decision.action == PolicyAction.REDACT,
                "detections_found": len(decision.detected_threats),
                "output_firewall_applied": settings.ENABLE_OUTPUT_FIREWALL,
                "output_action": output_action.value,
                "output_detections_found": output_detections_count,
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

    @staticmethod
    def _inspect_output_text(content: str) -> Tuple[str, bool, int]:
        """Inspect one text segment and return sanitized text, blocked flag, and detection count."""
        out_pipeline_res = detection_pipeline.run(content)
        out_decision = policy_engine.evaluate(content, out_pipeline_res)
        detection_count = len(out_decision.detected_threats)

        if out_decision.action == PolicyAction.BLOCK:
            return (
                "[RESPONSE BLOCKED BY PROMPTGUARD OUTPUT FIREWALL: Sensitive data or policy violation detected in LLM response]",
                True,
                detection_count,
            )
        if out_decision.action == PolicyAction.REDACT:
            return out_decision.redacted_prompt, False, detection_count
        return content, False, 0

    async def _forward_to_llm(
        self,
        payload: Dict[str, Any],
        demo_scenario: Optional[str] = None,
    ) -> Tuple[Dict[str, Any], int]:
        """Forward payload to an upstream LLM API or the controlled mock LLM."""
        if settings.MOCK_LLM_MODE or not settings.OPENAI_API_KEY:
            if demo_scenario is None:
                return await mock_llm_service.chat_completion(payload), 200
            return await mock_llm_service.chat_completion(payload, scenario=demo_scenario), 200

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
