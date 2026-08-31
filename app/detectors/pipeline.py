from typing import List
from app.detectors.pii import PIIDetector
from app.detectors.credentials import CredentialDetector
from app.detectors.financial import FinancialDetector
from app.detectors.intent import IntentClassifier
from app.models import PipelineResult, StageResult, DetectionMatch, ThreatSeverity
from app.config import settings

class DetectionPipeline:
    def __init__(self):
        self.stage1_pii = PIIDetector()
        self.stage2_credentials = CredentialDetector()
        self.stage3_financial = FinancialDetector()
        self.stage4_intent = IntentClassifier()

    def run(self, text: str) -> PipelineResult:
        stage_results: List[StageResult] = []
        all_matches: List[DetectionMatch] = []

        # Stage 1: PII
        if settings.ENABLE_STAGE_1_PII:
            res1 = self.stage1_pii.analyze(text)
            stage_results.append(res1)
            all_matches.extend(res1.matches)

        # Stage 2: Credentials
        if settings.ENABLE_STAGE_2_CREDENTIALS:
            res2 = self.stage2_credentials.analyze(text)
            stage_results.append(res2)
            all_matches.extend(res2.matches)

        # Stage 3: Financial
        if settings.ENABLE_STAGE_3_FINANCIAL:
            res3 = self.stage3_financial.analyze(text)
            stage_results.append(res3)
            all_matches.extend(res3.matches)

        # Stage 4: Intent
        if settings.ENABLE_STAGE_4_INTENT:
            res4 = self.stage4_intent.analyze(text)
            stage_results.append(res4)
            all_matches.extend(res4.matches)

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
