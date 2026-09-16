"""
GLiNER-based ML Credential Detector (Stage 2 - Layer 2)

Uses knowledgator/gliner-pii-base-v1.0 — a zero-shot NER model fine-tuned
for PII/secret detection. Labels are defined at runtime so the model can detect
credential types it was never explicitly trained on.

Loading follows the same background-thread pattern as intent_transformer.py to
avoid blocking FastAPI/Streamlit startup.
"""

import threading
import logging
import time
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Zero-shot label definitions ───────────────────────────────────────────────
# These plain-English labels are passed to GLiNER at inference time.
# No retraining needed — GLiNER understands what each label means contextually.
GLINER_SECRET_LABELS = [
    "api key",
    "secret key",
    "secret token",
    "access token",
    "bearer token",
    "password",
    "private key",
    "database credential",
    "database password",
    "webhook secret",
    "encryption key",
    "client secret",
    "auth token",
    "ssh key",
    "certificate",
]

# Minimum GLiNER confidence score to flag an entity
GLINER_THRESHOLD = 0.45

# Map GLiNER label → canonical entity_type used in DetectionMatch
_LABEL_TO_ENTITY = {
    "api key": "API_KEY",
    "secret key": "SECRET_KEY",
    "secret token": "SECRET_TOKEN",
    "access token": "ACCESS_TOKEN",
    "bearer token": "BEARER_TOKEN",
    "password": "PASSWORD",
    "private key": "PRIVATE_KEY",
    "database credential": "DB_CREDENTIAL",
    "database password": "DB_PASSWORD_ML",
    "webhook secret": "WEBHOOK_SECRET",
    "encryption key": "ENCRYPTION_KEY",
    "client secret": "CLIENT_SECRET",
    "auth token": "AUTH_TOKEN",
    "ssh key": "SSH_KEY",
    "certificate": "CERTIFICATE",
}

MODEL_ID = "knowledgator/gliner-pii-base-v1.0"


class GLiNERCredentialDetector:
    """
    Singleton that loads the GLiNER PII model in a background thread.
    Falls back to returning no predictions (empty list) if the model
    hasn't finished loading yet — the entropy scanner acts as backup.
    """

    _instance: Optional["GLiNERCredentialDetector"] = None
    _lock = threading.Lock()

    def __new__(cls) -> "GLiNERCredentialDetector":
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._model = None
                cls._instance._loading = False
                cls._instance._ready = False
                cls._instance._load_error: Optional[str] = None
        return cls._instance

    def ensure_loaded(self) -> None:
        """Trigger background model loading if not already started."""
        if not self._loading and not self._ready:
            self._loading = True
            thread = threading.Thread(
                target=self._load_model_worker,
                name="gliner-loader",
                daemon=True,
            )
            thread.start()

    def _load_model_worker(self) -> None:
        try:
            logger.info(f"[GLiNER] Loading model: {MODEL_ID} ...")
            t0 = time.time()
            from gliner import GLiNER  # type: ignore
            model = GLiNER.from_pretrained(MODEL_ID)
            self._model = model
            self._ready = True
            elapsed = time.time() - t0
            logger.info(f"[GLiNER] Model ready in {elapsed:.1f}s")
        except Exception as exc:
            self._load_error = str(exc)
            logger.error(f"[GLiNER] Failed to load model: {exc}")
        finally:
            self._loading = False

    @property
    def is_ready(self) -> bool:
        return self._ready and self._model is not None

    def predict(self, text: str) -> List[Tuple[str, str, int, int, float]]:
        """
        Run GLiNER NER inference on text.

        Returns a list of tuples:
            (entity_type, text_snippet, start, end, confidence)

        Returns empty list if the model is not yet loaded (fast startup
        guaranteed — entropy fallback handles this window).
        """
        if not self.is_ready:
            return []

        try:
            entities = self._model.predict_entities(
                text,
                GLINER_SECRET_LABELS,
                threshold=GLINER_THRESHOLD,
            )
            results = []
            for ent in entities:
                label = ent.get("label", "").lower()
                entity_type = _LABEL_TO_ENTITY.get(label, label.upper().replace(" ", "_"))
                results.append((
                    entity_type,
                    ent["text"],
                    ent["start"],
                    ent["end"],
                    float(ent.get("score", 0.8)),
                ))
            return results
        except Exception as exc:
            logger.warning(f"[GLiNER] Inference error: {exc}")
            return []


# Module-level singleton — imported by credentials.py
gliner_detector = GLiNERCredentialDetector()
