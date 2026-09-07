from pydantic import BaseModel, Field, model_validator
from typing import List, Optional, Dict, Any, Literal, Union
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


class DataClassification(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


class TextContentBlock(BaseModel):
    """The supported OpenAI-style content block for gateway inspection."""
    type: Literal["text"]
    text: str = Field(min_length=1, max_length=20_000)

class ChatMessage(BaseModel):
    role: Literal["system", "user", "assistant"]
    content: Union[str, List[TextContentBlock]]

    @model_validator(mode="after")
    def validate_content(self):
        if isinstance(self.content, str):
            if not self.content.strip():
                raise ValueError("message content must not be empty")
        elif not self.content:
            raise ValueError("message content blocks must not be empty")
        return self

    def text_content(self) -> str:
        if isinstance(self.content, str):
            return self.content
        return "\n".join(block.text for block in self.content)

class ChatCompletionRequest(BaseModel):
    model: str = "gpt-3.5-turbo"
    messages: List[ChatMessage] = Field(min_length=1, max_length=50)
    temperature: Optional[float] = Field(default=0.7, ge=0, le=2)
    max_tokens: Optional[int] = Field(default=1000, ge=1, le=4096)
    stream: Optional[bool] = False
    user: Optional[str] = "employee-default"

    @model_validator(mode="after")
    def validate_total_prompt_size(self):
        if sum(len(message.text_content()) for message in self.messages) > 20_000:
            raise ValueError("combined message content exceeds the 20,000 character limit")
        return self

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
    classifications: List[DataClassification] = Field(default_factory=list)
    highest_classification: DataClassification = DataClassification.PUBLIC

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
