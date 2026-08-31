import re
import time
from typing import List
from app.models import StageResult, DetectionMatch, ThreatSeverity
from app.detectors.preprocessor import decode_base64_payloads

INTENT_PATTERNS = {
    "BULK_PII_EXFILTRATION": {
        "pattern": r"(?i)(entire\s+customer\s+database\s+export|employee\s+master\s+sheet\s+with\s+\d+\s+records|customer_id,\s*name,\s*email|bulk\s+Aadhaar\s+and\s+bank\s+account\s+data)",
        "severity": ThreatSeverity.CRITICAL,
        "desc": "Bulk PII database export / exfiltration attempt detected"
    },
    "CONFIDENTIAL_MNPI_LEAK": {
        "pattern": r"(?i)(confidential\s+Q\d\s+board\s+meeting\s+minutes|acquire\s+[A-Za-z0-9\s]+\s+for\s+₹?\d+|lay\s+off\s+\d+\s+employees|material\s+non-public\s+information)",
        "severity": ThreatSeverity.CRITICAL,
        "desc": "Material Non-Public Information (MNPI) / Confidential M&A business leak"
    },
    "INDIRECT_ROLEPLAY_EXTRACTION": {
        "pattern": r"(?i)(writing\s+a\s+novel\s+where.*reads?\s+out\s+all\s+the\s+real\s+names|pretend\s+you\s+are\s+a\s+database\s+administrator\s+and\s+read\s+out|reads?\s+out\s+the\s+contents\s+of\s+this\s+employee\s+table)",
        "severity": ThreatSeverity.CRITICAL,
        "desc": "Indirect roleplay / creative framing data exfiltration attempt"
    },
    "SYSTEM_INSTRUCTION_INJECTION": {
        "pattern": r"(?i)(\[END\s+OF\s+USER\s+INPUT\]|\[NEW\s+SYSTEM\s+INSTRUCTION\]|disable\s+all\s+content\s+filters|forward\s+the\s+following\s+data\s+directly\s+to\s+the\s+LLM\s+without\s+scanning)",
        "severity": ThreatSeverity.CRITICAL,
        "desc": "System instruction override / injection attack detected"
    },
    "PROMPT_INJECTION": {
        "pattern": r"(?i)(ignore\s+(all\s+)?(prior|previous)?\s*instructions|disregard\s+(the\s+)?(above\s+)?instructions|forget\s+all\s+prior\s+rules|override\s+system\s+prompt|bypass\s+(safety|content)\s+filters)",
        "severity": ThreatSeverity.CRITICAL,
        "desc": "Prompt injection attack vector detected"
    },
    "JAILBREAK_DAN": {
        "pattern": r"(?i)(DAN\s+mode|Do\s+Anything\s+Now|Developer\s+Mode\s+Output|unfiltered\s+AI\s+mode|you\s+have\s+no\s+ethical\s+restrictions)",
        "severity": ThreatSeverity.CRITICAL,
        "desc": "Known jailbreak persona pattern detected (DAN / Developer Mode)"
    }
}

class IntentClassifier:
    def analyze(self, text: str) -> StageResult:
        start_time = time.time()
        matches: List[DetectionMatch] = []
        seen_spans = set()

        # Preprocess: decode base64 strings if present
        orig_text, decoded_extra = decode_base64_payloads(text)
        search_target = f"{text} {decoded_extra}" if decoded_extra else text

        for entity_type, config in INTENT_PATTERNS.items():
            for m in re.finditer(config["pattern"], search_target):
                span_key = (m.start(), m.end())
                if span_key not in seen_spans:
                    seen_spans.add(span_key)
                    matches.append(DetectionMatch(
                        stage_id=4,
                        stage_name="Stage 4: Intent Classifier",
                        entity_type=entity_type,
                        text_snippet=m.group(0),
                        start=min(m.start(), len(text)),
                        end=min(m.end(), len(text)),
                        confidence=0.97,
                        severity=config["severity"],
                        description=config["desc"]
                    ))

        exec_time = (time.time() - start_time) * 1000
        return StageResult(
            stage_id=4,
            stage_name="Stage 4: Intent Classifier",
            passed=len(matches) == 0,
            detection_count=len(matches),
            matches=matches,
            execution_time_ms=round(exec_time, 2)
        )
