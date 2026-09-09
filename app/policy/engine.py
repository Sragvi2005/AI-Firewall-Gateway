import json
from pathlib import Path
from typing import Dict, List

from app.models import DataClassification, DetectionMatch, PipelineResult, PolicyAction, PolicyDecision

ENTITY_PLACEHOLDERS: Dict[str, str] = {
    "EMAIL_ADDRESS": "[EMAIL_ADDRESS]", "PHONE_NUMBER": "[PHONE_NUMBER]", "NAME": "[NAME]",
    "DATE_OF_BIRTH": "[DATE_OF_BIRTH]", "DATE": "[DATE]", "LOCATION": "[LOCATION]",
    "AADHAAR": "[AADHAAR_REDACTED]", "PAN": "[PAN_REDACTED]", "PASSPORT": "[PASSPORT_REDACTED]",
    "CREDIT_CARD": "[CREDIT_CARD_REDACTED]", "EXPIRY": "[EXPIRY_REDACTED]", "CVV": "[CVV_REDACTED]",
    "BANK_ACCOUNT": "[BANK_ACCOUNT_REDACTED]", "IFSC": "[IFSC_REDACTED]", "DB_USER": "[DB_USER_REDACTED]",
    "DB_PASSWORD": "[DB_PASSWORD_REDACTED]", "DB_HOST": "[DB_HOST_REDACTED]",
    "JWT_TOKEN": "[JWT_TOKEN_REDACTED]", "AWS_ACCESS_KEY": "[AWS_ACCESS_KEY_REDACTED]",
    "AWS_SECRET_KEY": "[AWS_SECRET_KEY_REDACTED]", "GITHUB_TOKEN": "[GITHUB_TOKEN_REDACTED]",
    "GENERIC_API_KEY": "[GENERIC_API_KEY_REDACTED]",
    "GLINER_SECRET": "[CREDENTIAL_REDACTED]",
}
ACTION_RANK = {PolicyAction.ALLOW: 0, PolicyAction.REDACT: 1, PolicyAction.BLOCK: 2}
CLASSIFICATION_RANK = {DataClassification.PUBLIC: 0, DataClassification.INTERNAL: 1, DataClassification.CONFIDENTIAL: 2, DataClassification.RESTRICTED: 3}


class PolicyDecisionEngine:
    """Applies the repository-owned policy document to detection results."""

    def __init__(self, policy_path: Path | None = None):
        self.policy_path = policy_path or Path(__file__).with_name("policies.json")
        with self.policy_path.open(encoding="utf-8") as policy_file:
            self._policy_document = json.load(policy_file)

    def _rule_for(self, entity_type: str) -> Dict[str, str]:
        policies = self._policy_document["policies"]
        if entity_type in policies:
            return policies[entity_type]
        for key, rule in policies.items():
            if key.endswith("_") and entity_type.startswith(key):
                return rule
        return self._policy_document["default"]

    def evaluate(self, original_prompt: str, pipeline_result: PipelineResult) -> PolicyDecision:
        action = PolicyAction.ALLOW
        classifications = set()
        reasons: List[str] = []
        blocked_stage = None
        for match in pipeline_result.all_matches:
            rule = self._rule_for(match.entity_type)
            match_action = PolicyAction(rule["action"])
            classification = DataClassification(rule["classification"])
            classifications.add(classification)
            if ACTION_RANK[match_action] > ACTION_RANK[action]:
                action = match_action
            if match_action == PolicyAction.BLOCK and blocked_stage is None:
                blocked_stage = match.stage_name
            reasons.append(f"{match.entity_type}: {match_action.value} under {classification.value} policy")

        ordered = sorted(classifications, key=CLASSIFICATION_RANK.get)
        highest = ordered[-1] if ordered else DataClassification.PUBLIC
        if action == PolicyAction.ALLOW:
            reasons = ["No policy-controlled threats or sensitive data detected."]
        return PolicyDecision(
            action=action,
            original_prompt=original_prompt,
            redacted_prompt=("[REQUEST BLOCKED BY PROMPTGUARD FIREWALL]" if action == PolicyAction.BLOCK else self._apply_redaction(original_prompt, pipeline_result.all_matches)),
            reasons=reasons,
            detected_threats=pipeline_result.all_matches,
            blocked_by_stage=blocked_stage,
            classifications=ordered,
            highest_classification=highest,
        )

    def _apply_redaction(self, text: str, matches: List[DetectionMatch]) -> str:
        valid_matches = [match for match in matches if 0 <= match.start < match.end <= len(text)]
        for match in sorted(valid_matches, key=lambda item: item.start, reverse=True):
            placeholder = ENTITY_PLACEHOLDERS.get(match.entity_type, f"[{match.entity_type.upper()}_REDACTED]")
            text = text[:match.start] + placeholder + text[match.end:]
        return text


policy_engine = PolicyDecisionEngine()
