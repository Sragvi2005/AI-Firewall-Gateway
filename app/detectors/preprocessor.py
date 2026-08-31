import re
import base64
from typing import Tuple, Optional

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
