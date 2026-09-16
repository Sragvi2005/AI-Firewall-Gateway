import re
import time
import math
from typing import List
from app.models import StageResult, DetectionMatch, ThreatSeverity

CREDENTIAL_PATTERNS = {
    "OPENAI_API_KEY": {
        "pattern": r"\bsk-(proj-)?[A-Za-z0-9_-]{32,}\b",
        "severity": ThreatSeverity.CRITICAL,
        "placeholder": "[OPENAI_API_KEY_REDACTED]",
        "desc": "OpenAI API Key exposed"
    },
    "GITHUB_TOKEN": {
        "pattern": r"\bgh[pousr]_[A-Za-z0-9_]{36}\b",
        "severity": ThreatSeverity.CRITICAL,
        "placeholder": "[GITHUB_TOKEN_REDACTED]",
        "desc": "GitHub Token exposed"
    },
    "SLACK_TOKEN": {
        "pattern": r"\bxox[baprs]-[a-zA-Z0-9-]+\b",
        "severity": ThreatSeverity.HIGH,
        "placeholder": "[SLACK_TOKEN_REDACTED]",
        "desc": "Slack Token exposed"
    },
    "GCP_API_KEY": {
        "pattern": r"\bAIza[0-9A-Za-z-_]{35,}\b",
        "severity": ThreatSeverity.CRITICAL,
        "placeholder": "[GCP_API_KEY_REDACTED]",
        "desc": "Google Cloud / Firebase API Key exposed"
    },
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

REDACTION_MAPPING = {
    "STRIPE_SECRET_KEY": "[STRIPE_SECRET_KEY_REDACTED]",
    "SENDGRID_API_KEY": "[SENDGRID_API_KEY_REDACTED]",
    "HARDCODED_SUPERADMIN": "[HARDCODED_SUPERADMIN_REDACTED]",
    "GCP_API_KEY": "[GCP_API_KEY_REDACTED]",
    "OPENAI_API_KEY": "[OPENAI_API_KEY_REDACTED]",
    "GITHUB_TOKEN": "[GITHUB_TOKEN_REDACTED]",
    "SLACK_TOKEN": "[SLACK_TOKEN_REDACTED]",
    "ZERO_DAY_SECRET": "[ZERO_DAY_SECRET_REDACTED]"
}

def shannon_entropy(data: str) -> float:
    if not data:
        return 0
    entropy = 0.0
    length = len(data)
    frequencies = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1
    for count in frequencies.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return entropy

# Keywords that appear near secret assignments (e.g. api_key = "...", SECRET: "...")
GENERIC_SECRET_KEYWORDS = [
    "api_key", "apikey", "api-key", "secret", "token", "password", "passwd",
    "auth", "bearer", "key=", "key:", "pwd", "credential", "access_key",
    "private_key", "client_secret", "app_secret", "webhook_secret"
]

# Regex to detect key=value / key: value assignment patterns
_ASSIGNMENT_RE = re.compile(
    r"(?i)([a-z0-9_\-]{3,40})\s*(?:=|:)\s*[\"']?([A-Za-z0-9+/=_\-]{16,})[\"']?"
)

def _charset_diversity(token: str) -> dict:
    """Returns a dict of character class flags present in the token."""
    has_upper  = bool(re.search(r'[A-Z]', token))
    has_lower  = bool(re.search(r'[a-z]', token))
    has_digit  = bool(re.search(r'[0-9]', token))
    has_special = bool(re.search(r'[+/=_\-]', token))
    diversity = sum([has_upper, has_lower, has_digit, has_special])
    return {"upper": has_upper, "lower": has_lower, "digit": has_digit,
            "special": has_special, "diversity": diversity}

def _is_hex_string(token: str) -> bool:
    return bool(re.fullmatch(r'[0-9a-fA-F]+', token))

def _is_base64_like(token: str) -> bool:
    # Base64 uses A-Z, a-z, 0-9, +, /, = (padding)
    return bool(re.fullmatch(r'[A-Za-z0-9+/]+=*', token))

def _zero_day_secret_score(token: str, context_window: str) -> tuple[float, str]:
    """
    Scores a token on multiple heuristic signals. Returns (confidence, reason).
    Returns (0.0, '') if not suspicious.
    """
    entropy = shannon_entropy(token)
    length = len(token)
    diversity = _charset_diversity(token)
    is_hex = _is_hex_string(token)
    is_b64 = _is_base64_like(token)
    has_keyword = any(kw in context_window for kw in GENERIC_SECRET_KEYWORDS)

    score = 0.0
    reasons = []

    # Signal 1: High Shannon entropy for the token length
    if length > 16 and entropy > 3.8:
        score += 0.3
        reasons.append(f"high entropy ({entropy:.2f})")        

    # Signal 2: Contextual proximity to a secret keyword
    if has_keyword:
        score += 0.35
        reasons.append("near secret keyword")

    # Signal 3: Charset diversity (real keys mix upper, lower, digits, symbols)
    if diversity["diversity"] >= 3:
        score += 0.15
        reasons.append("high charset diversity")

    # Signal 4: Looks like a hex secret (32 or 64 hex chars = MD5 / SHA256)
    if is_hex and length in (32, 40, 56, 64):
        score += 0.25
        reasons.append(f"hex-encoded secret ({length} chars)")

    # Signal 5: Looks like a base64 token of typical key length
    if is_b64 and length >= 24:
        score += 0.2
        reasons.append("base64-encoded token")

    # Signal 6: Extremely long random string even without keyword (standalone dump)
    if length > 40 and entropy > 4.5:
        score += 0.3
        reasons.append("extra-long high-entropy string")

    if score >= 0.5:
        return min(score, 0.97), "; ".join(reasons)
    return 0.0, ''


class CredentialDetector:
    def __init__(self) -> None:
        # Kick off GLiNER model loading in background immediately
        from app.detectors.credential_gliner import gliner_detector
        self._gliner = gliner_detector
        self._gliner.ensure_loaded()

    def analyze(self, text: str) -> StageResult:
        start_time = time.time()
        matches: List[DetectionMatch] = []
        seen_spans = set()

        # ── Layer 1: Known-pattern regex scan ─────────────────────────────────
        # Fast, 0% false-positive for known API key formats
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

        # ── Layer 2: GLiNER ML Model (zero-shot NER) ──────────────────────────
        # Understands context: detects "password: MyDogName$2024" or
        # "webhook_secret: abcXYZ..." even with low-entropy human-readable values.
        # Falls back silently if the model hasn't finished loading yet.
        if self._gliner.is_ready:
            gliner_hits = self._gliner.predict(text)
            for entity_type, snippet, start_idx, end_idx, confidence in gliner_hits:
                span_key = (start_idx, end_idx)
                if span_key not in seen_spans:
                    seen_spans.add(span_key)
                    matches.append(DetectionMatch(
                        stage_id=2,
                        stage_name="Stage 2: Credential Scan",
                        entity_type=entity_type,
                        text_snippet=snippet,
                        start=start_idx,
                        end=end_idx,
                        confidence=confidence,
                        severity=ThreatSeverity.HIGH,
                        description=f"ML-detected credential via GLiNER NER model (label: {entity_type.lower().replace('_', ' ')})"
                    ))

        # ── Layer 3: Entropy Fallback ─────────────────────────────────────────
        # Handles the startup window before GLiNER is ready, and also catches
        # bare random strings with no surrounding context (e.g., a token pasted
        # alone without any key= label). Runs always for defence-in-depth.

        # Pass 1: Assignment-style patterns (var_name = "secret_value")
        for m in _ASSIGNMENT_RE.finditer(text):
            var_name  = m.group(1).lower()
            value     = m.group(2)
            start_idx = m.start(2)
            end_idx   = m.end(2)
            span_key  = (start_idx, end_idx)

            if span_key in seen_spans:
                continue

            confidence, reason = _zero_day_secret_score(value, var_name)
            if confidence > 0:
                seen_spans.add(span_key)
                matches.append(DetectionMatch(
                    stage_id=2,
                    stage_name="Stage 2: Credential Scan",
                    entity_type="ZERO_DAY_SECRET",
                    text_snippet=value,
                    start=start_idx,
                    end=end_idx,
                    confidence=confidence,
                    severity=ThreatSeverity.HIGH,
                    description=f"Zero-day secret detected via entropy heuristics: {reason}"
                ))

        # Pass 2: Bare high-entropy tokens not already caught above
        for m in re.finditer(r"[A-Za-z0-9+/=_\-]{16,}", text):
            token     = m.group(0)
            start_idx = m.start(0)
            end_idx   = m.end(0)
            span_key  = (start_idx, end_idx)

            if span_key in seen_spans:
                continue

            context_window = text[max(0, start_idx - 40):start_idx].lower()
            confidence, reason = _zero_day_secret_score(token, context_window)
            if confidence > 0:
                seen_spans.add(span_key)
                matches.append(DetectionMatch(
                    stage_id=2,
                    stage_name="Stage 2: Credential Scan",
                    entity_type="ZERO_DAY_SECRET",
                    text_snippet=token,
                    start=start_idx,
                    end=end_idx,
                    confidence=confidence,
                    severity=ThreatSeverity.HIGH,
                    description=f"Zero-day secret detected via entropy heuristics: {reason}"
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
