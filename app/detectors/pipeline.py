from typing import List, Optional, Dict, Any
from app.detectors.pii import PIIDetector
from app.detectors.credentials import CredentialDetector
from app.detectors.financial import FinancialDetector
from app.detectors.intent import IntentClassifier
from app.detectors.media_extractor import process_all_media
from app.models import PipelineResult, StageResult, DetectionMatch, ThreatSeverity
from app.config import settings
import logging

logger = logging.getLogger("promptguard.pipeline")


class DetectionPipeline:
    def __init__(self):
        self.stage1_pii = PIIDetector()
        self.stage2_credentials = CredentialDetector()
        self.stage3_financial = FinancialDetector()
        self.stage4_intent = IntentClassifier()

    def run(
        self,
        text: str,
        attachments: Optional[List[Dict[str, Any]]] = None
    ) -> PipelineResult:
        """
        Run the 4-stage detection pipeline on text AND media content.

        Args:
            text: The plain text content from the user message(s).
            attachments: Optional list of attachment dicts, each with:
                         {filename, content_base64, mime_type}
        """
        stage_results: List[StageResult] = []
        all_matches: List[DetectionMatch] = []
        media_scan_info: Optional[Dict[str, Any]] = None

        # ── Media Extraction ──────────────────────────────────────────────
        # Extract text from images/files and append to the text for scanning.
        # All detections from media text will have offset >= len(original_text).
        media_extracted_text = ""
        if settings.ENABLE_MEDIA_SCANNING and attachments:
            max_bytes = settings.MAX_ATTACHMENT_SIZE_MB * 1024 * 1024
            media_summary = process_all_media(attachments, max_size_bytes=max_bytes)

            if media_summary.combined_text:
                media_extracted_text = media_summary.combined_text
                logger.info(
                    f"Media scan: {media_summary.total_media_items} items, "
                    f"{media_summary.images_scanned} images, "
                    f"{media_summary.files_scanned} files, "
                    f"{media_summary.total_text_extracted} chars extracted"
                )

            media_scan_info = {
                "total_media_items": media_summary.total_media_items,
                "images_scanned": media_summary.images_scanned,
                "files_scanned": media_summary.files_scanned,
                "total_text_extracted": media_summary.total_text_extracted,
                "extractions": [
                    {
                        "source_type": e.source_type,
                        "filename": e.filename,
                        "mime_type": e.mime_type,
                        "char_count": e.char_count,
                        "success": e.success,
                        "error": e.error,
                        "method": e.method,
                    }
                    for e in media_summary.extractions
                ],
            }

        # Combine text + media-extracted text for full pipeline scanning
        # We mark the boundary so we can attribute detections to media sources
        text_boundary = len(text)
        combined_text = text
        if media_extracted_text:
            combined_text = text + "\n\n" + media_extracted_text

        # ── Stage 1: PII ──────────────────────────────────────────────────
        if settings.ENABLE_STAGE_1_PII:
            res1 = self.stage1_pii.analyze(combined_text)
            # Tag matches that came from media
            for m in res1.matches:
                if m.start >= text_boundary and media_scan_info:
                    m.source = f"media"
            stage_results.append(res1)
            all_matches.extend(res1.matches)

        # ── Stage 2: Credentials ──────────────────────────────────────────
        if settings.ENABLE_STAGE_2_CREDENTIALS:
            res2 = self.stage2_credentials.analyze(combined_text)
            for m in res2.matches:
                if m.start >= text_boundary and media_scan_info:
                    m.source = f"media"
            stage_results.append(res2)
            all_matches.extend(res2.matches)

        # ── Stage 3: Financial ────────────────────────────────────────────
        if settings.ENABLE_STAGE_3_FINANCIAL:
            res3 = self.stage3_financial.analyze(combined_text)
            for m in res3.matches:
                if m.start >= text_boundary and media_scan_info:
                    m.source = f"media"
            stage_results.append(res3)
            all_matches.extend(res3.matches)

        # ── Stage 4: Intent ──────────────────────────────────────────────
        if settings.ENABLE_STAGE_4_INTENT:
            res4 = self.stage4_intent.analyze(combined_text)
            for m in res4.matches:
                if m.start >= text_boundary and media_scan_info:
                    m.source = f"media"
            stage_results.append(res4)
            all_matches.extend(res4.matches)

        # ── Determine highest severity ────────────────────────────────────
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
            all_matches=all_matches,
            media_scan=media_scan_info
        )

# Global pipeline instance
detection_pipeline = DetectionPipeline()
