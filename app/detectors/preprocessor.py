import base64
import re
import unicodedata
from typing import Optional, Tuple


ZERO_WIDTH_CHARACTERS = "\u200b\u200c\u200d\u2060\ufeff"

# A deliberately small mapping for characters commonly substituted into attack
# phrases. It is not used for PII redaction, where preserving exact offsets is
# essential; it is only used by the blocking intent detector.
HOMOGLYPH_MAP = str.maketrans({
    "а": "a", "А": "A", "е": "e", "Е": "E", "і": "i", "І": "I",
    "о": "o", "О": "O", "р": "p", "Р": "P", "с": "c", "С": "C",
    "х": "x", "Х": "X", "у": "y", "У": "Y",
})


def normalize_for_intent_detection(text: str) -> Tuple[str, bool]:
    """Canonicalize text used for blocking-only intent detection.

    The return flag records whether the request contained an obfuscation signal.
    Keeping this transformation separate from the raw text avoids invalidating
    PII and credential redaction offsets.
    """
    normalized = unicodedata.normalize("NFKC", text)
    normalized = normalized.translate(HOMOGLYPH_MAP)
    normalized = normalized.translate(str.maketrans("", "", ZERO_WIDTH_CHARACTERS))
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized, normalized != text

def decode_base64_payloads(text: str) -> Tuple[str, Optional[str]]:
    """
    Scans for Base64 encoded strings inside text, decodes them if valid ASCII/UTF-8,
    and returns (original_text, decoded_extra_text).
    """
    b64_pattern = r"\b[A-Za-z0-9+/]{20,}={0,2}\b"
    matches = re.findall(b64_pattern, text)
    decoded_fragments = []

    for m in matches:
        try:
            decoded_bytes = base64.b64decode(m, validate=True)
            decoded_str = decoded_bytes.decode("utf-8")
            # Only accept readable text fragments
            if any(c.isalpha() for c in decoded_str):
                decoded_fragments.append(decoded_str)
        except Exception:
            pass

    if decoded_fragments:
        return text, " ".join(decoded_fragments)
    return text, None
