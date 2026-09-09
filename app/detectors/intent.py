import time
from typing import List
from app.models import StageResult, DetectionMatch, ThreatSeverity
from app.detectors.intent_transformer import transformer_intent_classifier

class IntentClassifier:
    """
    Stage 4: Adversarial Intent & Jailbreak Classifier using a deep learning / transformer
    intent classification model rather than hardcoded pattern matching.
    """
    def __init__(self):
        self.model = transformer_intent_classifier

    def analyze(self, text: str) -> StageResult:
        start_time = time.time()
        matches: List[DetectionMatch] = []

        prediction = self.model.predict(text)

        if prediction.is_threat:
            start_idx, end_idx = prediction.detected_span
            matches.append(DetectionMatch(
                stage_id=4,
                stage_name="Stage 4: Intent Classifier",
                entity_type=prediction.intent_class,
                text_snippet=prediction.detected_snippet,
                start=start_idx,
                end=end_idx,
                confidence=prediction.confidence,
                severity=prediction.severity,
                description=prediction.description
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
