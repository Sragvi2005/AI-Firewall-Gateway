import time
import uuid
from fastapi import APIRouter, Request, Query
from typing import Optional, Dict, Any
from app.models import ChatCompletionRequest, InspectionRequest, PolicyAction
from app.services.proxy import proxy_service
from app.detectors.pipeline import detection_pipeline
from app.policy.engine import policy_engine
from app.compliance.audit import audit_logger

router = APIRouter()

@router.post("/v1/chat/completions")
async def chat_completions(request: ChatCompletionRequest, req: Request):
    """
    OpenAI-compatible Chat Completions proxy endpoint.
    Intercepts prompt -> 4-Stage Detection Pipeline -> Policy Decision (ALLOW/REDACT/BLOCK) -> Forward to LLM.
    """
    client_ip = req.client.host if req.client else "127.0.0.1"
    return await proxy_service.process_chat_completion(request, client_ip)

@router.post("/api/chat")
async def chat_with_inspection(request: ChatCompletionRequest, req: Request):
    """
    Combined Chat + Inspection endpoint for the PromptGuard Chat UI.
    Runs the 4-stage pipeline, evaluates the policy decision, forwards to the
    upstream LLM (or mock), logs the audit, and returns both the LLM response
    and the full security analysis in one call.
    """
    start_time = time.time()
    request_id = f"req-{uuid.uuid4().hex[:12]}"
    client_ip = req.client.host if req.client else "127.0.0.1"
    user_id = request.user or "chat-ui-user"

    # Extract the user-role prompt text for pipeline analysis
    user_prompt = "\n".join(
        msg.content for msg in request.messages if msg.role == "user"
    )
    combined_prompt = "\n".join(
        f"{msg.role}: {msg.content}" for msg in request.messages
    )

    # 1. Run 4-stage detection pipeline
    pipeline_result = detection_pipeline.run(user_prompt)

    # 2. Policy Decision
    decision = policy_engine.evaluate(user_prompt, pipeline_result)

    # 3. Build security analysis payload
    security_analysis = {
        "action": decision.action.value,
        "original_prompt": decision.original_prompt,
        "redacted_prompt": decision.redacted_prompt,
        "reasons": decision.reasons,
        "blocked_by_stage": decision.blocked_by_stage,
        "pipeline": {
            "total_detections": pipeline_result.total_detections,
            "highest_severity": pipeline_result.highest_severity.value,
            "stages": [
                {
                    "stage_id": s.stage_id,
                    "stage_name": s.stage_name,
                    "passed": s.passed,
                    "detection_count": s.detection_count,
                    "execution_time_ms": s.execution_time_ms,
                    "matches": [
                        {
                            "entity_type": m.entity_type,
                            "text_snippet": m.text_snippet,
                            "confidence": m.confidence,
                            "severity": m.severity.value,
                            "description": m.description,
                        }
                        for m in s.matches
                    ],
                }
                for s in pipeline_result.stage_results
            ],
        },
    }

    # 4a. If BLOCK — do not forward to LLM
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
        return {
            "request_id": request_id,
            "message": {"role": "assistant", "content": None},
            "blocked": True,
            "security": security_analysis,
            "latency_ms": round(latency_ms, 2),
        }

    # 4b. If ALLOW or REDACT — forward (possibly sanitized) payload to LLM
    target_payload = request.model_dump()
    if decision.action == PolicyAction.REDACT:
        for msg in target_payload.get("messages", []):
            if msg.get("role") == "user":
                msg["content"] = policy_engine._apply_redaction(
                    msg["content"], pipeline_result.all_matches
                )

    llm_response, status_code = await proxy_service._forward_to_llm(target_payload)
    latency_ms = (time.time() - start_time) * 1000

    # Extract assistant text from LLM response
    assistant_content = ""
    if isinstance(llm_response, dict) and "choices" in llm_response:
        choices = llm_response["choices"]
        if choices and "message" in choices[0]:
            assistant_content = choices[0]["message"].get("content", "")

    # 5. Audit log
    audit_logger.log_request(
        request_id=request_id,
        client_ip=client_ip,
        user_id=user_id,
        original_prompt=combined_prompt,
        decision=decision,
        status_code=status_code,
        latency_ms=latency_ms,
    )

    return {
        "request_id": request_id,
        "message": {"role": "assistant", "content": assistant_content},
        "blocked": False,
        "security": security_analysis,
        "latency_ms": round(latency_ms, 2),
    }

@router.post("/api/inspect")
async def inspect_prompt(request: InspectionRequest):
    """
    Inspect a prompt against all 4 stages of the PromptGuard pipeline without calling the upstream LLM.
    """
    pipeline_res = detection_pipeline.run(request.prompt)
    decision = policy_engine.evaluate(request.prompt, pipeline_res)
    return {
        "prompt": request.prompt,
        "action": decision.action,
        "redacted_prompt": decision.redacted_prompt,
        "reasons": decision.reasons,
        "blocked_by_stage": decision.blocked_by_stage,
        "pipeline": pipeline_res.model_dump()
    }

@router.get("/api/audit-logs")
async def get_audit_logs(
    limit: int = Query(50, ge=1, le=500),
    action: Optional[str] = Query(None, description="ALLOW, REDACT, or BLOCK"),
    search: Optional[str] = Query(None, description="Search prompt or user")
):
    """
    Fetch audit logs recorded by the gateway.
    """
    return audit_logger.fetch_logs(limit=limit, action_filter=action, search=search)

@router.get("/api/analytics")
async def get_analytics():
    """
    Get aggregated detection analytics and metrics.
    """
    return audit_logger.fetch_analytics()
