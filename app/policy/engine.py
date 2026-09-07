from typing import List, Dict
from app.models import PipelineResult, PolicyDecision, PolicyAction, ThreatSeverity, DetectionMatch

# Exact placeholder tags as requested in user specification
ENTITY_PLACEHOLDERS: Dict[str, str] = {
    "EMAIL_ADDRESS": "[EMAIL_ADDRESS]",
    "PHONE_NUMBER": "[PHONE_NUMBER]",
    "NAME": "[NAME]",
    "DATE_OF_BIRTH": "[DATE_OF_BIRTH]",
    "DATE": "[DATE]",
    "LOCATION": "[LOCATION]",
    "AADHAAR": "[AADHAAR_REDACTED]",
    "PAN": "[PAN_REDACTED]",
    "PASSPORT": "[PASSPORT_REDACTED]",
    "JWT_TOKEN": "[JWT_TOKEN_REDACTED]",
    "AWS_ACCESS_KEY": "[AWS_ACCESS_KEY_REDACTED]",
    "AWS_SECRET_KEY": "[AWS_SECRET_KEY_REDACTED]",
    "DB_USER": "[DB_USER_REDACTED]",
    "DB_PASSWORD": "[DB_PASSWORD_REDACTED]",
    "DB_HOST": "[DB_HOST_REDACTED]",
    "CREDIT_CARD": "[CREDIT_CARD_REDACTED]",
    "EXPIRY": "[EXPIRY_REDACTED]",
    "CVV": "[CVV_REDACTED]",
    "BANK_ACCOUNT": "[BANK_ACCOUNT_REDACTED]",
    "IFSC": "[IFSC_REDACTED]",
    "STRIPE_SECRET_KEY": "[STRIPE_SECRET_KEY_REDACTED]",
    "SENDGRID_API_KEY": "[SENDGRID_API_KEY_REDACTED]",
    "GITHUB_TOKEN": "[GITHUB_TOKEN_REDACTED]",
    "GENERIC_API_KEY": "[GENERIC_API_KEY_REDACTED]",
    "HARDCODED_SUPERADMIN": "[HARDCODED_SUPERADMIN_REDACTED]"
}

class PolicyDecisionEngine:
    def evaluate(self, original_prompt: str, pipeline_result: PipelineResult) -> PolicyDecision:
        if pipeline_result.total_detections == 0:
            return PolicyDecision(
                action=PolicyAction.ALLOW,
                original_prompt=original_prompt,
                redacted_prompt=original_prompt,
                reasons=["No security threats or sensitive data detected."],
                detected_threats=[],
                blocked_by_stage=None
            )

        reasons: List[str] = []
        should_block = False
        blocked_stage = None

        # Check Blocking Triggers:
        # 1. Intent Stage threats (Prompt Injection, Jailbreak, Bulk PII Dumps, MNPI, Roleplay Extraction, Obfuscation, Injection)
        # 2. Critical Multi-Secret Config Leaks (Stripe Secret Key, SendGrid API Key, Hardcoded Superadmin)
        for match in pipeline_result.all_matches:
            if match.stage_id == 4:
                should_block = True
                blocked_stage = match.stage_name
                reasons.append(f"Blocked due to security policy violation: {match.entity_type} ({match.description})")
            elif match.severity == ThreatSeverity.CRITICAL:
                should_block = True
                blocked_stage = match.stage_name
                reasons.append(f"Blocked due to CRITICAL threat finding: {match.entity_type} ({match.description})")

        if should_block:
            return PolicyDecision(
                action=PolicyAction.BLOCK,
                original_prompt=original_prompt,
                redacted_prompt="[REQUEST BLOCKED BY PROMPTGUARD FIREWALL]",
                reasons=reasons,
                detected_threats=pipeline_result.all_matches,
                blocked_by_stage=blocked_stage
            )

        # Redaction Path
        redacted_text = self._apply_redaction(original_prompt, pipeline_result.all_matches)
        for match in pipeline_result.all_matches:
            reasons.append(f"Redacted sensitive field: {match.entity_type} ({match.description})")

        return PolicyDecision(
            action=PolicyAction.REDACT,
            original_prompt=original_prompt,
            redacted_prompt=redacted_text,
            reasons=reasons,
            detected_threats=pipeline_result.all_matches,
            blocked_by_stage=None
        )

    def _apply_redaction(self, text: str, matches: List[DetectionMatch]) -> str:
        """Replace detected sensitive text spans with specified placeholder tags."""
        if not matches:
            return text

        # Sort matches in reverse order of start index to prevent index shifting
        sorted_matches = sorted(matches, key=lambda m: m.start, reverse=True)
        redacted = list(text)

        for match in sorted_matches:
            placeholder = ENTITY_PLACEHOLDERS.get(match.entity_type, f"[{match.entity_type.upper()}_REDACTED]")
            start = match.start
            end = match.end
            redacted[start:end] = list(placeholder)

        return "".join(redacted)

policy_engine = PolicyDecisionEngine()
