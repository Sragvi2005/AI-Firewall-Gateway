from fastapi import APIRouter, Request, Query
from typing import Optional
from app.models import ChatCompletionRequest, InspectionRequest
from app.services.proxy import proxy_service
from app.detectors.pipeline import detection_pipeline
from app.policy.engine import policy_engine
from app.compliance.audit import audit_logger

router = APIRouter()


@router.post("/v1/direct-chat")
async def direct_chat(request: ChatCompletionRequest):
    """Controlled baseline: forward to the mock/upstream LLM without inspection."""
    return await proxy_service.process_direct_chat(request)


@router.post("/v1/chat/completions")
async def chat_completions(request: ChatCompletionRequest, req: Request):
    """OpenAI-compatible protected chat-completions endpoint."""
    client_ip = req.client.host if req.client else "127.0.0.1"
    return await proxy_service.process_chat_completion(request, client_ip)


@router.post("/api/inspect")
async def inspect_prompt(request: InspectionRequest):
    """Inspect a prompt without calling the upstream LLM."""
    pipeline_res = detection_pipeline.run(request.prompt)
    decision = policy_engine.evaluate(request.prompt, pipeline_res)
    return {
        "prompt": request.prompt,
        "action": decision.action,
        "redacted_prompt": decision.redacted_prompt,
        "reasons": decision.reasons,
        "blocked_by_stage": decision.blocked_by_stage,
        "classifications": [classification.value for classification in decision.classifications],
        "highest_classification": decision.highest_classification.value,
        "pipeline": pipeline_res.model_dump(),
    }


@router.get("/api/audit-logs")
async def get_audit_logs(
    limit: int = Query(50, ge=1, le=500),
    action: Optional[str] = Query(None, description="ALLOW, REDACT, or BLOCK"),
    search: Optional[str] = Query(None, description="Search prompt or user"),
):
    return audit_logger.fetch_logs(limit=limit, action_filter=action, search=search)


@router.get("/api/analytics")
async def get_analytics():
    return audit_logger.fetch_analytics()
