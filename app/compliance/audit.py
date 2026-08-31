import sqlite3
import json
import os
import time
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from app.models import AuditLogEntry, PolicyDecision, PolicyAction
from app.config import settings

os.makedirs(settings.LOGS_DIR, exist_ok=True)
logging.basicConfig(
    filename=settings.AUDIT_LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("PromptGuardAudit")

class AuditLogger:
    def __init__(self, db_path: str = settings.AUDIT_DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    request_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    original_prompt TEXT NOT NULL,
                    redacted_prompt TEXT NOT NULL,
                    detections_count INTEGER NOT NULL,
                    detections_json TEXT NOT NULL,
                    status_code INTEGER NOT NULL,
                    latency_ms REAL NOT NULL
                )
            """)
            conn.commit()

    def log_request(
        self,
        request_id: str,
        client_ip: str,
        user_id: str,
        original_prompt: str,
        decision: PolicyDecision,
        status_code: int,
        latency_ms: float
    ) -> AuditLogEntry:
        timestamp_str = datetime.now(timezone.utc).isoformat()
        detections_summary = [
            {
                "stage_id": d.stage_id,
                "stage_name": d.stage_name,
                "entity_type": d.entity_type,
                "text_snippet": d.text_snippet,
                "severity": d.severity.value if hasattr(d.severity, 'value') else d.severity,
                "confidence": d.confidence
            }
            for d in decision.detected_threats
        ]

        entry = AuditLogEntry(
            request_id=request_id,
            timestamp=timestamp_str,
            client_ip=client_ip,
            user=user_id,
            original_prompt=original_prompt,
            action=decision.action,
            redacted_prompt=decision.redacted_prompt,
            detections_count=len(decision.detected_threats),
            detections_summary=detections_summary,
            status_code=status_code,
            latency_ms=round(latency_ms, 2)
        )

        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO audit_logs (
                        request_id, timestamp, client_ip, user_id, action,
                        original_prompt, redacted_prompt, detections_count,
                        detections_json, status_code, latency_ms
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    entry.request_id,
                    entry.timestamp,
                    entry.client_ip,
                    entry.user,
                    entry.action.value,
                    entry.original_prompt,
                    entry.redacted_prompt,
                    entry.detections_count,
                    json.dumps(entry.detections_summary),
                    entry.status_code,
                    entry.latency_ms
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to log to audit DB: {str(e)}")

        logger.info(json.dumps(entry.model_dump()))
        return entry

    def fetch_logs(self, limit: int = 100, action_filter: Optional[str] = None, search: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            query = "SELECT * FROM audit_logs WHERE 1=1"
            params = []

            if action_filter and action_filter != "ALL":
                query += " AND action = ?"
                params.append(action_filter)

            if search:
                query += " AND (original_prompt LIKE ? OR user_id LIKE ? OR detections_json LIKE ?)"
                search_param = f"%{search}%"
                params.extend([search_param, search_param, search_param])

            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            rows = cursor.fetchall()
            logs = []
            for r in rows:
                log_dict = dict(r)
                log_dict["detections_json"] = json.loads(log_dict["detections_json"])
                logs.append(log_dict)
            return logs

    def fetch_analytics(self) -> Dict[str, Any]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM audit_logs")
            total = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE action = 'ALLOW'")
            allow_cnt = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE action = 'REDACT'")
            redact_cnt = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE action = 'BLOCK'")
            block_cnt = cursor.fetchone()[0]

            cursor.execute("SELECT detections_json FROM audit_logs WHERE detections_count > 0")
            all_dets = cursor.fetchall()

            stage_counts = {"Stage 1: PII": 0, "Stage 2: Credentials": 0, "Stage 3: Financial": 0, "Stage 4: Intent": 0}
            for (det_str,) in all_dets:
                try:
                    dets = json.loads(det_str)
                    for d in dets:
                        st = d.get("stage_id", 0)
                        if st == 1: stage_counts["Stage 1: PII"] += 1
                        elif st == 2: stage_counts["Stage 2: Credentials"] += 1
                        elif st == 3: stage_counts["Stage 3: Financial"] += 1
                        elif st == 4: stage_counts["Stage 4: Intent"] += 1
                except Exception:
                    pass

            return {
                "total_requests": total,
                "allow_count": allow_cnt,
                "redact_count": redact_cnt,
                "block_count": block_cnt,
                "stage_counts": stage_counts
            }

audit_logger = AuditLogger()
