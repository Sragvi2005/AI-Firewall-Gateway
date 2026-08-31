import re
import time
from typing import List
from app.models import StageResult, DetectionMatch, ThreatSeverity

CREDENTIAL_PATTERNS = {
    "JWT_TOKEN": {
        "pattern": r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+(?:\.[A-Za-z0-9-_.+/=]+)?\b",
        "severity": ThreatSeverity.HIGH,
        "placeholder": "[JWT_TOKEN_REDACTED]",
        "desc": "JSON Web Token (JWT) exposed"
    },
    "AWS_ACCESS_KEY": {
        "pattern": r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",
        "severity": ThreatSeverity.HIGH,
        "placeholder": "[AWS_ACCESS_KEY_REDACTED]",
        "desc": "AWS Access Key ID exposed"
    },
    "AWS_SECRET_KEY": {
        "pattern": r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "severity": ThreatSeverity.HIGH,
        "placeholder": "[AWS_SECRET_KEY_REDACTED]",
        "desc": "AWS Secret Access Key exposed"
    },
    "DB_USER": {
        "pattern": r"postgresql://([^:]+):",
        "severity": ThreatSeverity.HIGH,
        "placeholder": "[DB_USER_REDACTED]",
        "desc": "Database User in Connection String"
    },
    "DB_PASSWORD": {
        "pattern": r"postgresql://[^:]+:([^@]+(?:\@[^@]+)*)@(?=[a-zA-Z0-9.-]+:\d+)",
        "severity": ThreatSeverity.HIGH,
        "placeholder": "[DB_PASSWORD_REDACTED]",
        "desc": "Database Password in Connection String"
    },
    "DB_HOST": {
        "pattern": r"postgresql://[^:]+:[^@]+(?:\@[^@]+)*@([a-zA-Z0-9.-]+):\d+",
        "severity": ThreatSeverity.HIGH,
        "placeholder": "[DB_HOST_REDACTED]",
        "desc": "Database Host in Connection String"
    },
    "STRIPE_SECRET_KEY": {
        "pattern": r"\bsk_live_[0-9a-zA-Z]{24,}\b",
        "severity": ThreatSeverity.CRITICAL,
        "placeholder": "[STRIPE_SECRET_KEY_REDACTED]",
        "desc": "Stripe Live Secret Key"
    },
    "SENDGRID_API_KEY": {
        "pattern": r"\bSG\.[a-zA-Z0-9_-]{20,}\b",
        "severity": ThreatSeverity.CRITICAL,
        "placeholder": "[SENDGRID_API_KEY_REDACTED]",
        "desc": "SendGrid Live API Key"
    },
    "HARDCODED_SUPERADMIN": {
        "pattern": r"(?i)(pass(word)?\s*===?\s*['\"]Adm!n@C0mpany2024['\"]|DB_PASS=Pr0d@Root#2024|ROLE_SUPERADMIN)",
        "severity": ThreatSeverity.CRITICAL,
        "placeholder": "[HARDCODED_SUPERADMIN_REDACTED]",
        "desc": "Hardcoded Superadmin / Prod DB Master Credential"
    }
}

class CredentialDetector:
    def analyze(self, text: str) -> StageResult:
        start_time = time.time()
        matches: List[DetectionMatch] = []
        seen_spans = set()

        for entity_type, config in CREDENTIAL_PATTERNS.items():
            for m in re.finditer(config["pattern"], text):
                matched_snippet = m.group(1) if (m.lastindex and m.lastindex >= 1 and m.group(1)) else m.group(0)
                start_idx = m.start(1) if (m.lastindex and m.lastindex >= 1 and m.group(1)) else m.start(0)
                end_idx = m.end(1) if (m.lastindex and m.lastindex >= 1 and m.group(1)) else m.end(0)
                span_key = (start_idx, end_idx)

                if span_key not in seen_spans:
                    seen_spans.add(span_key)
                    matches.append(DetectionMatch(
                        stage_id=2,
                        stage_name="Stage 2: Credential Scan",
                        entity_type=entity_type,
                        text_snippet=matched_snippet,
                        start=start_idx,
                        end=end_idx,
                        confidence=0.98,
                        severity=config["severity"],
                        description=config["desc"]
                    ))

        exec_time = (time.time() - start_time) * 1000
        return StageResult(
            stage_id=2,
            stage_name="Stage 2: Credential Scan",
            passed=len(matches) == 0,
            detection_count=len(matches),
            matches=matches,
            execution_time_ms=round(exec_time, 2)
        )
