import time
import logging
import math
import re
from typing import List, Optional, Tuple, Dict, Any
from app.models import StageResult, DetectionMatch, ThreatSeverity
from app.config import settings

logger = logging.getLogger("promptguard.gliner")

# Labels specifically targeting credentials, secrets, tokens, and keys
GLINER_CREDENTIAL_LABELS = [
    "api key",
    "secret key",
    "access token",
    "authentication token",
    "bearer token",
    "private key",
    "database credential",
    "database password",
    "database connection string",
    "cloud credential",
    "service account credential",
    "Firebase credential",
    "AWS credential",
    "GCP credential",
    "Azure credential",
    "GitHub token",
    "payment API key",
    "webhook secret",
    "encryption key",
    "client secret",
    "OAuth secret",
    "JWT",
    "credential",
    "secret",
]

# Non-secret explanatory terms / words that might be tagged as concept mentions rather than secret values
BENIGN_CONCEPT_KEYWORDS = {
    "api key", "api keys", "secret key", "secret keys", "access token", "access tokens",
    "database password", "database passwords", "secret", "secrets", "credential", "credentials",
    "bearer token", "private key", "client secret", "oauth secret", "password", "passwords",
    "token", "tokens", "key", "keys", "system", "environment variables", "config", "configuration"
}


class ShannonEntropyCalculator:
    @staticmethod
    def calculate(text: str) -> float:
        if not text or len(text) < 2:
            return 0.0
        freq: Dict[str, int] = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / len(text)
            entropy -= p * math.log2(p)
        return entropy


class GLiNERSingletonModel:
    """Loads GLiNER model once at application startup and keeps it resident."""
    _instance: Optional["GLiNERSingletonModel"] = None
    _model = None
    _loaded: bool = False
    _load_failed: bool = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(GLiNERSingletonModel, cls).__new__(cls)
        return cls._instance

    def load_model(self):
        if self._loaded or self._load_failed:
            return
        if not settings.ENABLE_GLINER:
            logger.info("GLiNER is disabled via configuration (ENABLE_GLINER=False).")
            return
        try:
            logger.info("Loading GLiNER model: %s", settings.GLINER_MODEL_NAME)
            from gliner import GLiNER
            self._model = GLiNER.from_pretrained(settings.GLINER_MODEL_NAME)
            self._loaded = True
            logger.info("GLiNER model loaded successfully.")
        except Exception as exc:
            self._load_failed = True
            logger.warning("Failed to load GLiNER model (%s). Fallback to deterministic rules: %s", settings.GLINER_MODEL_NAME, exc)

    @property
    def model(self):
        if not self._loaded and not self._load_failed:
            self.load_model()
        return self._model

    @property
    def is_available(self) -> bool:
        if not self._loaded and not self._load_failed:
            self.load_model()
        return self._loaded and self._model is not None


gliner_singleton = GLiNERSingletonModel()


class GLiNERCredentialDetector:
    """
    ML-assisted zero-shot entity extraction detector using GLiNER.
    Identifies unknown, proprietary, or custom credential/secret formats.
    Includes context, entropy, and length validation to suppress false positives.
    """

    def __init__(self, model_loader: Optional[GLiNERSingletonModel] = None):
        self.loader = model_loader or gliner_singleton

    def _extract_candidate_token(self, full_text: str, start: int, end: int, snippet: str) -> Tuple[str, int, int]:
        """
        If GLiNER highlighted a concept phrase (e.g. 'internal token: super_secret_123'),
        extract the actual candidate token value and adjust span offsets.
        """
        cleaned_snippet = snippet.strip()
        # If snippet itself is a long high-entropy string
        if len(cleaned_snippet) >= 8 and not any(cleaned_snippet.casefold() == b for b in BENIGN_CONCEPT_KEYWORDS):
            return cleaned_snippet, start, end

        # Look in immediate right context for assigned value (e.g. : 'xyz' or = xyz)
        after_text = full_text[end:end + 120]
        assign_match = re.search(r"^\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.\/+=!@#$%^&*]{8,})['\"]?", after_text)
        if assign_match:
            val = assign_match.group(1)
            val_start = end + assign_match.start(1)
            val_end = end + assign_match.end(1)
            return val, val_start, val_end

        # Look for token right after snippet
        token_match = re.search(r"^\s+([A-Za-z0-9_\-\.\/+=]{12,})", after_text)
        if token_match:
            val = token_match.group(1)
            val_start = end + token_match.start(1)
            val_end = end + token_match.end(1)
            return val, val_start, val_end

        return cleaned_snippet, start, end

    def _is_valid_secret_candidate(self, token: str, label: str) -> bool:
        """
        Suppresses false positives:
        - Rejects benign concept names ('API key', 'secret', 'password')
        - Checks minimum length and character diversity
        - Analyzes Shannon entropy
        """
        normalized_token = token.strip().casefold()
        if normalized_token in BENIGN_CONCEPT_KEYWORDS:
            return False

        # Words with spaces are descriptive phrases rather than secret tokens,
        # unless it's a pass-phrase with sufficient length & entropy
        if " " in token and len(token) < 20:
            return False

        # Secret tokens should have minimum length
        if len(token) < 8:
            return False

        entropy = ShannonEntropyCalculator.calculate(token)
        char_diversity = len(set(token)) / len(token) if token else 0.0

        # Heuristic 1: If it has reasonable length (>= 12) and entropy >= 3.0
        if len(token) >= 12 and entropy >= 2.8 and char_diversity >= 0.3:
            return True

        # Heuristic 2: Known secret prefixes / structures (even if short)
        if re.match(r"^(sk_|pk_|ghp_|gho_|xox[baprs]-|AKIA|ASIA|SG\.|AIza)", token, re.IGNORECASE):
            return True

        # Heuristic 3: High entropy password or secret (length >= 8, entropy >= 3.2, digits/mixed case)
        has_digit = any(c.isdigit() for c in token)
        has_upper = any(c.isupper() for c in token)
        has_lower = any(c.islower() for c in token)
        if len(token) >= 8 and entropy >= 3.2 and ((has_digit and has_lower) or (has_upper and has_lower)):
            return True

        return False

    def analyze(self, text: str) -> StageResult:
        start_time = time.time()
        matches: List[DetectionMatch] = []

        if not settings.ENABLE_GLINER or not self.loader.is_available:
            exec_time = (time.time() - start_time) * 1000
            return StageResult(
                stage_id=5,
                stage_name="Stage 5: GLiNER ML Secret Detector",
                passed=True,
                detection_count=0,
                matches=[],
                execution_time_ms=round(exec_time, 2),
            )

        try:
            raw_entities = self.loader.model.predict_entities(
                text,
                GLINER_CREDENTIAL_LABELS,
                threshold=0.28,
            )

            seen_spans = set()
            for entity in raw_entities:
                raw_snippet = entity.get("text", "")
                raw_start = entity.get("start", 0)
                raw_end = entity.get("end", 0)
                label = entity.get("label", "secret")
                score = float(entity.get("score", 0.0))

                candidate_token, cand_start, cand_end = self._extract_candidate_token(
                    text, raw_start, raw_end, raw_snippet
                )

                if self._is_valid_secret_candidate(candidate_token, label):
                    span_key = (cand_start, cand_end)
                    if span_key not in seen_spans:
                        seen_spans.add(span_key)
                        entropy = round(ShannonEntropyCalculator.calculate(candidate_token), 2)
                        matches.append(
                            DetectionMatch(
                                stage_id=5,
                                stage_name="Stage 5: GLiNER ML Secret Detector",
                                entity_type="GLINER_SECRET",
                                text_snippet=candidate_token,
                                start=cand_start,
                                end=cand_end,
                                confidence=round(min(0.99, max(0.65, score)), 2),
                                severity=ThreatSeverity.HIGH,
                                description=(
                                    f"ML zero-shot detection ({label}) with entropy={entropy}, "
                                    f"length={len(candidate_token)}"
                                ),
                            )
                        )
        except Exception as exc:
            logger.warning("GLiNER inference error (falling back safely): %s", exc)

        exec_time = (time.time() - start_time) * 1000
        return StageResult(
            stage_id=5,
            stage_name="Stage 5: GLiNER ML Secret Detector",
            passed=len(matches) == 0,
            detection_count=len(matches),
            matches=matches,
            execution_time_ms=round(exec_time, 2),
        )
