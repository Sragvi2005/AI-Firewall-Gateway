from typing import List
from app.detectors.pii import PIIDetector
from app.detectors.credentials import CredentialDetector
from app.detectors.financial import FinancialDetector
from app.detectors.intent import IntentClassifier
from app.detectors.gliner_detector import GLiNERCredentialDetector
from app.models import PipelineResult, StageResult, DetectionMatch, ThreatSeverity
from app.config import settings

class DetectionPipeline:
    def __init__(self):
        self.stage1_pii = PIIDetector()
        self.stage2_credentials = CredentialDetector()
        self.stage3_financial = FinancialDetector()
        self.stage4_intent = IntentClassifier()
        self.stage5_gliner = GLiNERCredentialDetector()

    def _deduplicate_matches(self, rule_matches: List[DetectionMatch], gliner_matches: List[DetectionMatch]) -> List[DetectionMatch]:
        """Consolidates findings that overlap in span or cover the same secret token.

        Rule-based detections have deterministic patterns and take priority for entity naming,
        while recording that GLiNER ML also confirmed the secret.
        """
        consolidated = list(rule_matches)
        for g_match in gliner_matches:
            overlapped = False
            for idx, r_match in enumerate(consolidated):
                # Check for character span overlap
                has_span_overlap = not (g_match.end <= r_match.start or g_match.start >= r_match.end)
                # Or exact text snippet containment
                has_text_overlap = (
                    (g_match.text_snippet in r_match.text_snippet or r_match.text_snippet in g_match.text_snippet)
                    and len(g_match.text_snippet) >= 6
                )
                if has_span_overlap or has_text_overlap:
                    overlapped = True
                    # Consolidate: update description with ML co-confirmation and boost confidence
                    new_conf = max(r_match.confidence, g_match.confidence)
                    consolidated[idx] = DetectionMatch(
                        stage_id=r_match.stage_id,
                        stage_name=r_match.stage_name,
                        entity_type=r_match.entity_type,
                        text_snippet=r_match.text_snippet,
                        start=min(r_match.start, g_match.start),
                        end=max(r_match.end, g_match.end),
                        confidence=new_conf,
                        severity=r_match.severity,
                        description=f"{r_match.description} [Confirmed by ML GLiNER]",
                    )
                    break
            if not overlapped:
                consolidated.append(g_match)
        return consolidated

    def run(self, text: str) -> PipelineResult:
        stage_results: List[StageResult] = []
        rule_matches: List[DetectionMatch] = []
        gliner_matches: List[DetectionMatch] = []

        # Stage 1: PII
        if settings.ENABLE_STAGE_1_PII:
            res1 = self.stage1_pii.analyze(text)
            stage_results.append(res1)
            rule_matches.extend(res1.matches)

        # Stage 2: Credentials
        if settings.ENABLE_STAGE_2_CREDENTIALS:
            res2 = self.stage2_credentials.analyze(text)
            stage_results.append(res2)
            rule_matches.extend(res2.matches)

        # Stage 3: Financial
        if settings.ENABLE_STAGE_3_FINANCIAL:
            res3 = self.stage3_financial.analyze(text)
            stage_results.append(res3)
            rule_matches.extend(res3.matches)

        # Stage 4: Intent
        if settings.ENABLE_STAGE_4_INTENT:
            res4 = self.stage4_intent.analyze(text)
            stage_results.append(res4)
            rule_matches.extend(res4.matches)

        # Stage 5: GLiNER ML Secret Detection
        if settings.ENABLE_GLINER:
            res5 = self.stage5_gliner.analyze(text)
            stage_results.append(res5)
            gliner_matches.extend(res5.matches)

        # Consolidate overlapping rule and GLiNER detections
        all_matches = self._deduplicate_matches(rule_matches, gliner_matches)

        # Determine highest severity
        highest_severity = ThreatSeverity.INFO
        has_critical_or_high = False

        severity_rank = {
            ThreatSeverity.CRITICAL: 4,
            ThreatSeverity.HIGH: 3,
            ThreatSeverity.MEDIUM: 2,
            ThreatSeverity.LOW: 1,
            ThreatSeverity.INFO: 0
        }

        max_rank = 0
        for match in all_matches:
            rank = severity_rank.get(match.severity, 0)
            if rank > max_rank:
                max_rank = rank
                highest_severity = match.severity
            if match.severity in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH]:
                has_critical_or_high = True

        return PipelineResult(
            total_detections=len(all_matches),
            highest_severity=highest_severity,
            has_critical_or_high=has_critical_or_high,
            stage_results=stage_results,
            all_matches=all_matches
        )

# Global pipeline instance
detection_pipeline = DetectionPipeline()
