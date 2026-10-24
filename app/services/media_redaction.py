"""Outbound media sanitization for multimodal chat payloads.

Provides helpers to:
1. Pixel-redact inline images and PDF pages before forwarding to the LLM.
2. Build multimodal content arrays that include sanitized media so the
   upstream LLM receives redacted versions of images/PDFs rather than
   having them silently stripped.
"""

from typing import Any, Dict, List, Optional, Tuple

from app.detectors.media_extractor import (
    _resolve_mime_type,
    _decode_base64_content,
    redact_image_base64,
    redact_pdf_base64,
    IMAGE_MIME_TYPES,
)
from app.models import DetectionMatch
from app.policy.engine import ENTITY_PLACEHOLDERS
import logging
import base64

logger = logging.getLogger("promptguard.media_redaction")


# ── Helpers ──────────────────────────────────────────────────────────────────

def _redact_text_with_matches(text: str, matches: List[DetectionMatch]) -> str:
    """Apply snippet-based redaction on a plain text string using matches."""
    redacted = text
    for match in sorted(matches, key=lambda m: len(m.text_snippet), reverse=True):
        snippet = match.text_snippet
        if not snippet:
            continue
        placeholder = ENTITY_PLACEHOLDERS.get(
            match.entity_type, f"[{match.entity_type.upper()}_REDACTED]"
        )
        redacted = redacted.replace(snippet, placeholder)
    return redacted


def _extract_pdf_text_for_forwarding(content_base64: str) -> Optional[str]:
    """Extract plain text from a base64-encoded PDF for text-only forwarding."""
    try:
        from PyPDF2 import PdfReader
        import io
        pdf_bytes = _decode_base64_content(content_base64)
        reader = PdfReader(io.BytesIO(pdf_bytes))
        pages = []
        for page in reader.pages:
            page_text = page.extract_text()
            if page_text:
                pages.append(page_text)
        return "\n".join(pages).strip() if pages else None
    except Exception as e:
        logger.warning("Could not extract PDF text for forwarding: %s", e)
        return None


# ── Single-attachment sanitization ───────────────────────────────────────────

def sanitize_attachment(
    attachment: Dict[str, Any], matches: List[DetectionMatch]
) -> Optional[Dict[str, Any]]:
    """Produce a sanitized replacement for a detected image or PDF attachment."""
    if not matches:
        return None
    filename = attachment.get("filename", "attachment")
    content = attachment.get("content_base64", "")
    mime_type = _resolve_mime_type(filename, attachment.get("mime_type"))

    if mime_type.startswith("image/"):
        sanitized = redact_image_base64(content, matches)
    elif mime_type == "application/pdf":
        sanitized = redact_pdf_base64(content, matches)
    else:
        sanitized = None

    if not sanitized:
        return None
    return {
        "filename": filename,
        "content_base64": sanitized,
        "mime_type": mime_type,
    }


# ── Inline-image redaction (existing) ────────────────────────────────────────

def redact_inline_images(
    payload: Dict[str, Any], matches: List[DetectionMatch]
) -> int:
    """Redact detected inline image pixels, removing the image on failure.

    Images without media findings remain unchanged.
    """
    media_matches = [m for m in matches if m.source.startswith("media:")]
    if not media_matches:
        return 0

    redacted_count = 0
    for message in payload.get("messages", []):
        content = message.get("content")
        if not isinstance(content, list):
            continue

        sanitized_parts = []
        for part in content:
            if not isinstance(part, dict) or part.get("type") != "image_url":
                sanitized_parts.append(part)
                continue

            image_url = part.get("image_url", {})
            url = image_url.get("url", "") if isinstance(image_url, dict) else str(image_url)
            if not url.startswith("data:"):
                sanitized_parts.append(part)
                continue

            filename = "inline_image"
            image_matches = [m for m in media_matches if m.source == f"media:{filename}"]
            if not image_matches:
                sanitized_parts.append(part)
                continue

            redacted_image = redact_image_base64(url, image_matches)
            if redacted_image:
                sanitized_url = dict(image_url, url=redacted_image) if isinstance(image_url, dict) else redacted_image
                sanitized_parts.append({"type": "image_url", "image_url": sanitized_url})
            else:
                sanitized_parts.append({
                    "type": "text",
                    "text": "[Image removed because sensitive text could not be safely redacted.]",
                })
            redacted_count += 1

        message["content"] = sanitized_parts

    return redacted_count


# ── Build sanitized multimodal content for LLM forwarding ────────────────────

def build_sanitized_media_parts(
    attachments: List[Dict[str, Any]],
    all_matches: List[DetectionMatch],
) -> List[Dict[str, Any]]:
    """Build multimodal content parts from attachments after redacting detections.

    For each attachment:
      - Images → pixel-redacted base64 PNG as ``image_url`` content part
      - PDFs → pixel-redacted PDF converted to text, or text extracted + redacted
      - Text/code/docs → extracted text with snippet-based redaction as ``text`` part
      - If redaction fails entirely → a ``text`` placeholder part

    Clean attachments (no detections) are forwarded unchanged as image_url (images)
    or as extracted-text parts (documents).

    Returns a list of OpenAI-compatible multimodal content parts ready to be
    appended to a message's ``content`` array.
    """
    parts: List[Dict[str, Any]] = []
    media_matches = [m for m in all_matches if m.source.startswith("media:")]

    for attachment in attachments:
        filename = attachment.get("filename", "attachment")
        content_b64 = attachment.get("content_base64", "")
        mime_type = _resolve_mime_type(filename, attachment.get("mime_type"))

        # Gather matches specific to this attachment
        file_matches = [m for m in media_matches if m.source == f"media:{filename}"]

        if mime_type in IMAGE_MIME_TYPES:
            # ── IMAGE ────────────────────────────────────────────────────
            if file_matches:
                redacted_data_uri = redact_image_base64(content_b64, file_matches)
                if redacted_data_uri:
                    parts.append({
                        "type": "image_url",
                        "image_url": {"url": redacted_data_uri, "detail": "auto"},
                    })
                    logger.info("Forwarding pixel-redacted image: %s", filename)
                else:
                    # Pixel redaction failed — do NOT forward the original
                    parts.append({
                        "type": "text",
                        "text": (
                            f"[Image '{filename}' contained sensitive data that could "
                            f"not be safely redacted. The image was removed by PromptGuard.]"
                        ),
                    })
                    logger.warning(
                        "Image pixel redaction failed for %s — replaced with placeholder", filename
                    )
            else:
                # Clean image — forward as-is
                data_uri = content_b64
                if not data_uri.startswith("data:"):
                    data_uri = f"data:{mime_type};base64,{content_b64}"
                parts.append({
                    "type": "image_url",
                    "image_url": {"url": data_uri, "detail": "auto"},
                })

        elif mime_type == "application/pdf":
            # ── PDF ──────────────────────────────────────────────────────
            if file_matches:
                redacted_pdf_uri = redact_pdf_base64(content_b64, file_matches)
                if redacted_pdf_uri:
                    # Extract text from the *redacted* PDF for text-based forwarding
                    redacted_text = _extract_pdf_text_for_forwarding(redacted_pdf_uri)
                    if redacted_text:
                        parts.append({
                            "type": "text",
                            "text": f"[Sanitized content from PDF '{filename}']:\n{redacted_text}",
                        })
                        logger.info("Forwarding text from redacted PDF: %s", filename)
                    else:
                        parts.append({
                            "type": "text",
                            "text": (
                                f"[PDF '{filename}' was redacted by PromptGuard but "
                                f"text extraction from the sanitized copy failed.]"
                            ),
                        })
                else:
                    # PyMuPDF redaction failed — try text extraction + snippet redaction
                    raw_text = _extract_pdf_text_for_forwarding(content_b64)
                    if raw_text:
                        redacted_text = _redact_text_with_matches(raw_text, file_matches)
                        parts.append({
                            "type": "text",
                            "text": f"[Sanitized content from PDF '{filename}']:\n{redacted_text}",
                        })
                        logger.info(
                            "PDF pixel-redaction unavailable for %s — forwarding text-redacted content",
                            filename,
                        )
                    else:
                        parts.append({
                            "type": "text",
                            "text": (
                                f"[PDF '{filename}' contained sensitive data that could "
                                f"not be safely redacted. The document was removed by PromptGuard.]"
                            ),
                        })
            else:
                # Clean PDF — extract and forward text
                raw_text = _extract_pdf_text_for_forwarding(content_b64)
                if raw_text:
                    parts.append({
                        "type": "text",
                        "text": f"[Content from PDF '{filename}']:\n{raw_text}",
                    })
                # If extraction fails, skip silently (nothing to forward)

        else:
            # ── TEXT / DOCX / XLSX / CSV / CODE ──────────────────────────
            # These are already text-based; extract and forward with redaction
            from app.detectors.media_extractor import extract_from_attachment
            result = extract_from_attachment(content_b64, filename, mime_type)
            if result.success and result.extracted_text:
                text = result.extracted_text
                if file_matches:
                    text = _redact_text_with_matches(text, file_matches)
                    parts.append({
                        "type": "text",
                        "text": f"[Sanitized content from '{filename}']:\n{text}",
                    })
                    logger.info("Forwarding text-redacted document: %s", filename)
                else:
                    parts.append({
                        "type": "text",
                        "text": f"[Content from '{filename}']:\n{text}",
                    })
            elif file_matches:
                # Extraction failed but detections exist — block forward
                parts.append({
                    "type": "text",
                    "text": (
                        f"[File '{filename}' contained sensitive data that could "
                        f"not be safely redacted. The file was removed by PromptGuard.]"
                    ),
                })

    return parts


def inject_sanitized_media_into_payload(
    payload: Dict[str, Any],
    attachments: List[Dict[str, Any]],
    all_matches: List[DetectionMatch],
) -> int:
    """Inject sanitized media parts into the last user message of the LLM payload.

    Converts the message content to multimodal format (list of parts) if needed,
    then appends the sanitized media parts built by ``build_sanitized_media_parts``.

    Returns the number of media parts injected.
    """
    media_parts = build_sanitized_media_parts(attachments, all_matches)

    # Find the last user message
    messages = payload.get("messages", [])
    last_user_msg = None
    for msg in reversed(messages):
        if msg.get("role") == "user":
            last_user_msg = msg
            break

    if not last_user_msg:
        return 0

    # Inline data images are also included in ``attachments`` for scanning.
    # Remove every original data image from every message before adding the
    # scanned replacements. Removing only from the final user message left
    # originals in earlier turns of a multi-message conversation.
    for message in messages:
        content = message.get("content", "")
        if not isinstance(content, list):
            continue
        sanitized_content = []
        for part in content:
            if isinstance(part, dict) and part.get("type") == "image_url":
                image = part.get("image_url", {})
                url = image.get("url", "") if isinstance(image, dict) else str(image)
                if url.startswith("data:"):
                    continue
            sanitized_content.append(part)
        message["content"] = sanitized_content

    # Fail closed if no replacement part could be constructed. In particular,
    # never leave an inspected inline image in the payload just because media
    # conversion returned no parts.
    if not media_parts:
        logger.warning("No replacement media parts were created; original inline images were removed")
        return 0

    content = last_user_msg.get("content", "")

    # Convert string content to multimodal array format
    if isinstance(content, str):
        last_user_msg["content"] = [{"type": "text", "text": content}] + media_parts
    elif isinstance(content, list):
        last_user_msg["content"] = content + media_parts
    else:
        last_user_msg["content"] = [{"type": "text", "text": str(content)}] + media_parts

    logger.info("Injected %d sanitized media parts into LLM payload", len(media_parts))
    return len(media_parts)
