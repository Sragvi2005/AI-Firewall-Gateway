from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum

class PolicyAction(str, Enum):
    ALLOW = "ALLOW"
    REDACT = "REDACT"
    BLOCK = "BLOCK"

class ThreatSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatCompletionRequest(BaseModel):
    model: str = "gpt-3.5-turbo"
    messages: List[ChatMessage]
    temperature: Optional[float] = 0.7
    max_tokens: Optional[int] = 1000
    stream: Optional[bool] = False
    user: Optional[str] = "employee-default"

class InspectionRequest(BaseModel):
    prompt: str
    user: Optional[str] = "test-user"

class DetectionMatch(BaseModel):
    stage_id: int # 1: PII, 2: Credentials, 3: Financial, 4: Intent
    stage_name: str # e.g. "PII Detection", "Credential Scan", "Financial Data", "Intent Classifier"
    entity_type: str # e.g. EMAIL_ADDRESS, AWS_ACCESS_KEY, CREDIT_CARD, PROMPT_INJECTION
    text_snippet: str
    start: int
    end: int
    confidence: float # 0.0 to 1.0
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    description: str

class StageResult(BaseModel):
    stage_id: int
    stage_name: str
    passed: bool
    detection_count: int
    matches: List[DetectionMatch]
    execution_time_ms: float

class PipelineResult(BaseModel):
    total_detections: int
    highest_severity: ThreatSeverity
    has_critical_or_high: bool
    stage_results: List[StageResult]
    all_matches: List[DetectionMatch]

class PolicyDecision(BaseModel):
    action: PolicyAction
    original_prompt: str
    redacted_prompt: str
    reasons: List[str]
    detected_threats: List[DetectionMatch]
    blocked_by_stage: Optional[str] = None

class AuditLogEntry(BaseModel):
    request_id: str
    timestamp: str
    client_ip: str
    user: str
    original_prompt: str
    action: PolicyAction
    redacted_prompt: str
    detections_count: int
    detections_summary: List[Dict[str, Any]]
    status_code: int
    latency_ms: float
