import re
import time
from typing import List
from app.models import StageResult, DetectionMatch, ThreatSeverity

def luhn_checksum_valid(card_number_str: str) -> bool:
    """Validate credit card number using Luhn algorithm."""
    digits = [int(c) for c in re.sub(r"\D", "", card_number_str)]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = d * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += d
    return checksum % 10 == 0

FINANCIAL_PATTERNS = {
    "CREDIT_CARD": {
        "pattern": r"\b(?:\d{4}[-\s]?){3}\d{4}\b|\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        "severity": ThreatSeverity.HIGH,
        "placeholder": "[CREDIT_CARD_REDACTED]",
        "desc": "Credit Card Number detected"
    },
    "EXPIRY": {
        "pattern": r"(?i)\b(?:Expiry|Exp)\s*[:=]?\s*(\d{2}/\d{2})\b",
        "severity": ThreatSeverity.MEDIUM,
        "placeholder": "[EXPIRY_REDACTED]",
        "desc": "Credit Card Expiry Date detected"
    },
    "CVV": {
        "pattern": r"(?i)\b(?:cvv|cvc|security\s+code)\s*[:=]?\s*(\d{3,4})\b",
        "severity": ThreatSeverity.HIGH,
        "placeholder": "[CVV_REDACTED]",
        "desc": "Card Verification Value (CVV/CVC) detected"
    },
    "IFSC": {
        "pattern": r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
        "severity": ThreatSeverity.HIGH,
        "placeholder": "[IFSC_REDACTED]",
        "desc": "Indian Financial System Code (IFSC) detected"
    },
    "BANK_ACCOUNT": {
        "pattern": r"(?i)\b(?:Account\s+(?:No|Number)|Account)\s*[:=]?\s*(\d{9,18})\b",
        "severity": ThreatSeverity.HIGH,
        "placeholder": "[BANK_ACCOUNT_REDACTED]",
        "desc": "Bank Account Number detected"
    }
}

class FinancialDetector:
    def analyze(self, text: str) -> StageResult:
        start_time = time.time()
        matches: List[DetectionMatch] = []
        seen_spans = set()

        for entity_type, config in FINANCIAL_PATTERNS.items():
            for m in re.finditer(config["pattern"], text):
                matched_snippet = m.group(1) if (m.lastindex and m.lastindex >= 1 and m.group(1)) else m.group(0)
                start_idx = m.start(1) if (m.lastindex and m.lastindex >= 1 and m.group(1)) else m.start(0)
                end_idx = m.end(1) if (m.lastindex and m.lastindex >= 1 and m.group(1)) else m.end(0)
                span_key = (start_idx, end_idx)

                if entity_type == "CREDIT_CARD":
                    lower_surrounding = text[max(0, start_idx-30):min(len(text), end_idx+30)].lower()
                    has_card_context = any(k in lower_surrounding for k in ["card", "payment", "receipt", "charge", "subscript"])
                    if has_card_context or luhn_checksum_valid(matched_snippet):
                        if span_key not in seen_spans:
                            seen_spans.add(span_key)
                            matches.append(DetectionMatch(
                                stage_id=3,
                                stage_name="Stage 3: Financial Data",
                                entity_type=entity_type,
                                text_snippet=matched_snippet,
                                start=start_idx,
                                end=end_idx,
                                confidence=0.98,
                                severity=config["severity"],
                                description=config["desc"]
                            ))
                else:
                    if span_key not in seen_spans:
                        seen_spans.add(span_key)
                        matches.append(DetectionMatch(
                            stage_id=3,
                            stage_name="Stage 3: Financial Data",
                            entity_type=entity_type,
                            text_snippet=matched_snippet,
                            start=start_idx,
                            end=end_idx,
                            confidence=0.92,
                            severity=config["severity"],
                            description=config["desc"]
                        ))

        exec_time = (time.time() - start_time) * 1000
        return StageResult(
            stage_id=3,
            stage_name="Stage 3: Financial Data",
            passed=len(matches) == 0,
            detection_count=len(matches),
            matches=matches,
            execution_time_ms=round(exec_time, 2)
        )
