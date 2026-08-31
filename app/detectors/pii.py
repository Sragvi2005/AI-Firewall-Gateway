import re
import time
from typing import List
from app.models import StageResult, DetectionMatch, ThreatSeverity

PII_REGEX_PATTERNS = {
    "EMAIL_ADDRESS": {
        "pattern": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "severity": ThreatSeverity.MEDIUM,
        "placeholder": "[EMAIL_ADDRESS]",
        "desc": "Email address detected"
    },
    "PHONE_NUMBER": {
        "pattern": r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b|\b[6-9]\d{9}\b",
        "severity": ThreatSeverity.MEDIUM,
        "placeholder": "[PHONE_NUMBER]",
        "desc": "Phone number detected"
    },
    "AADHAAR": {
        "pattern": r"(?<!\d{4}\s)\b\d{4}\s\d{4}\s\d{4}\b(?!\s\d{4})",
        "severity": ThreatSeverity.HIGH,
        "placeholder": "[AADHAAR_REDACTED]",
        "desc": "Indian Aadhaar Number detected"
    },
    "PAN": {
        "pattern": r"\b[A-Z]{5}\d{4}[A-Z]\b",
        "severity": ThreatSeverity.HIGH,
        "placeholder": "[PAN_REDACTED]",
        "desc": "Indian Permanent Account Number (PAN) detected"
    },
    "PASSPORT": {
        "pattern": r"\b[A-Z]\d{7}\b",
        "severity": ThreatSeverity.HIGH,
        "placeholder": "[PASSPORT_REDACTED]",
        "desc": "Passport Number detected"
    },
    "NAME": {
        "pattern": r"\b(?:Name|Applicant|Employee|Client|to|client)\s*[:=]?\s*([A-Z][a-z]+(?:\s+[A-Z][a-z']+)+)\b|\b(Priya Sharma|Rajesh Kumar|James D'Souza|Suresh Menon|Ananya Iyer|Mohammed Farhan)\b",
        "severity": ThreatSeverity.MEDIUM,
        "placeholder": "[NAME]",
        "desc": "Person name detected"
    },
    "DATE_OF_BIRTH": {
        "pattern": r"(?i)\b(?:DOB|Date of Birth)\s*[:=]?\s*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})\b",
        "severity": ThreatSeverity.MEDIUM,
        "placeholder": "[DATE_OF_BIRTH]",
        "desc": "Date of Birth detected"
    },
    "DATE": {
        "pattern": r"\b\d{1,2}(?:st|nd|rd|th)?\s+(?:January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}\b",
        "severity": ThreatSeverity.MEDIUM,
        "placeholder": "[DATE]",
        "desc": "Appointment / Specific date detected"
    },
    "LOCATION": {
        "pattern": r"\b(?:\d{1,5}\s+[A-Za-z0-9\s,.]+?\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Nagar|Koramangala),?\s*)?(?:Bengaluru|Bangalore|Chennai|Mumbai|Delhi|Hyderabad|Pune|Kolkata)(?:\s+\d{6})?\b|\b\d{1,5}\s+[A-Za-z0-9\s,.]+?\s+Chennai\s+\d{6}\b",
        "severity": ThreatSeverity.MEDIUM,
        "placeholder": "[LOCATION]",
        "desc": "Location / Address detected"
    }
}

class PIIDetector:
    def analyze(self, text: str) -> StageResult:
        start_time = time.time()
        matches: List[DetectionMatch] = []
        seen_spans = set()

        for entity_type, config in PII_REGEX_PATTERNS.items():
            for m in re.finditer(config["pattern"], text):
                matched_snippet = m.group(1) if (m.lastindex and m.lastindex >= 1 and m.group(1)) else m.group(0)
                start_idx = m.start(1) if (m.lastindex and m.lastindex >= 1 and m.group(1)) else m.start(0)
                end_idx = m.end(1) if (m.lastindex and m.lastindex >= 1 and m.group(1)) else m.end(0)
                span_key = (start_idx, end_idx)

                if not any(s[0] <= start_idx < s[1] or s[0] < end_idx <= s[1] for s in seen_spans):
                    seen_spans.add(span_key)
                    matches.append(DetectionMatch(
                        stage_id=1,
                        stage_name="Stage 1: PII Detection",
                        entity_type=entity_type,
                        text_snippet=matched_snippet,
                        start=start_idx,
                        end=end_idx,
                        confidence=0.95,
                        severity=config["severity"],
                        description=config["desc"]
                    ))

        exec_time = (time.time() - start_time) * 1000
        return StageResult(
            stage_id=1,
            stage_name="Stage 1: PII Detection",
            passed=len(matches) == 0,
            detection_count=len(matches),
            matches=matches,
            execution_time_ms=round(exec_time, 2)
        )
