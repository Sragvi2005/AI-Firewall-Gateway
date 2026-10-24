"""
Media Content Extractor for PromptGuard AI Firewall Gateway.

Extracts readable text from images (via OCR) and document files (PDF, DOCX, XLSX, CSV, TXT, etc.)
so the existing 4-stage detection pipeline can scan media for sensitive data.

Works with ANY LLM — extraction is done server-side before forwarding.
"""

import base64
import io
import re
import logging
import zipfile
import xml.etree.ElementTree as ET
from typing import List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger("promptguard.media")

# ── Optional imports (graceful degradation) ──────────────────────────────────

_TESSERACT_AVAILABLE = False
_PIL_AVAILABLE = False
_PYPDF2_AVAILABLE = False
_DOCX_AVAILABLE = False
_OPENPYXL_AVAILABLE = False

try:
    from PIL import Image
    _PIL_AVAILABLE = True
except ImportError:
    logger.warning("Pillow not installed — image processing disabled")

try:
    import pytesseract
    _TESSERACT_AVAILABLE = True
except ImportError:
    logger.warning("pytesseract not installed — image OCR disabled")

try:
    from PyPDF2 import PdfReader
    _PYPDF2_AVAILABLE = True
except ImportError:
    logger.warning("PyPDF2 not installed — PDF extraction disabled")

_PYMUPDF_AVAILABLE = False
try:
    import fitz
    _PYMUPDF_AVAILABLE = True
except ImportError:
    logger.warning("PyMuPDF not installed — PDF redaction disabled")

try:
    import docx
    _DOCX_AVAILABLE = True
except ImportError:
    logger.warning("python-docx not installed — DOCX extraction disabled")

try:
    import openpyxl
    _OPENPYXL_AVAILABLE = True
except ImportError:
    logger.warning("openpyxl not installed — XLSX extraction disabled")


# ── Supported MIME types ─────────────────────────────────────────────────────

IMAGE_MIME_TYPES = {"image/png", "image/jpeg", "image/jpg", "image/gif", "image/bmp", "image/tiff", "image/webp"}

DOCUMENT_MIME_TYPES = {
    "application/pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",  # .docx
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",         # .xlsx
    "application/vnd.openxmlformats-officedocument.presentationml.presentation", # .pptx
    "application/vnd.oasis.opendocument.text",                                    # .odt
    "text/csv",
    "text/plain",
    "application/json",
    "application/xml",
    "text/xml",
    "text/yaml",
    "text/x-yaml",
    "application/x-yaml",
}

# Extension → MIME fallback map
EXTENSION_MIME_MAP = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".bmp": "image/bmp",
    ".tiff": "image/tiff",
    ".tif": "image/tiff",
    ".webp": "image/webp",
    ".pdf": "application/pdf",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".odt": "application/vnd.oasis.opendocument.text",
    ".csv": "text/csv",
    ".txt": "text/plain",
    ".log": "text/plain",
    ".env": "text/plain",
    ".ini": "text/plain",
    ".conf": "text/plain",
    ".cfg": "text/plain",
    ".json": "application/json",
    ".xml": "application/xml",
    ".yaml": "text/yaml",
    ".yml": "text/yaml",
    ".md": "text/plain",
    ".py": "text/plain",
    ".js": "text/plain",
    ".ts": "text/plain",
    ".java": "text/plain",
    ".go": "text/plain",
    ".rs": "text/plain",
    ".rb": "text/plain",
    ".sh": "text/plain",
    ".sql": "text/plain",
    ".html": "text/plain",
    ".css": "text/plain",
}


@dataclass
class MediaExtractionResult:
    """Result of extracting text from a single media item."""
    source_type: str          # "image" or "file"
    filename: str             # Original filename or "inline_image"
    mime_type: str             # Detected MIME type
    extracted_text: str        # All text extracted from this media
    char_count: int = 0        # Number of characters extracted
    success: bool = True       # Whether extraction succeeded
    error: str = ""            # Error message if failed
    method: str = ""           # Extraction method used (e.g., "tesseract_ocr", "pypdf2", "direct_read")
    combined_start: int = 0     # Start offset in MediaScanSummary.combined_text
    combined_end: int = 0       # End offset in MediaScanSummary.combined_text


@dataclass
class MediaScanSummary:
    """Summary of all media extraction performed on a request."""
    total_media_items: int = 0
    images_scanned: int = 0
    files_scanned: int = 0
    total_text_extracted: int = 0        # total characters
    extractions: List[MediaExtractionResult] = field(default_factory=list)
    combined_text: str = ""              # All extracted text concatenated


def _resolve_mime_type(filename: str, provided_mime: Optional[str] = None) -> str:
    """Resolve MIME type from filename extension if not provided."""
    if provided_mime and provided_mime != "application/octet-stream":
        return provided_mime
    if filename:
        ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        return EXTENSION_MIME_MAP.get(ext, "application/octet-stream")
    return "application/octet-stream"


def _decode_base64_content(content_base64: str) -> bytes:
    """Decode base64 content, handling data URI prefix."""
    # Strip data URI prefix if present (e.g., "data:image/png;base64,...")
    if "," in content_base64 and content_base64.startswith("data:"):
        content_base64 = content_base64.split(",", 1)[1]
    return base64.b64decode(content_base64, validate=True)


def _extract_text_from_ooxml(file_bytes: bytes, filename: str, kind: str) -> MediaExtractionResult:
    """Extract visible text from PPTX and ODT containers without loading media parts."""
    mime = (
        "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        if kind == "pptx" else "application/vnd.oasis.opendocument.text"
    )
    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes)) as archive:
            names = archive.namelist()
            if len(names) > 20_000 or sum(archive.getinfo(name).file_size for name in names) > 32 * 1024 * 1024:
                raise ValueError("document archive exceeds extraction limits")
            if kind == "pptx":
                parts = sorted(
                    name for name in names
                    if re.fullmatch(r"ppt/slides/slide\d+\.xml", name)
                    or re.fullmatch(r"ppt/notesSlides/notesSlide\d+\.xml", name)
                )
            else:
                parts = ["content.xml"] if "content.xml" in names else []
            if not parts:
                raise ValueError("document contains no readable text parts")
            chunks = []
            for name in parts:
                info = archive.getinfo(name)
                if info.file_size > 8 * 1024 * 1024:
                    raise ValueError("document text part exceeds extraction limit")
                root = ET.fromstring(archive.read(name))
                chunks.extend(value.strip() for value in root.itertext() if value.strip())
        text = "\n".join(chunks).strip()
        if not text:
            raise ValueError("no readable text found")
        return MediaExtractionResult("file", filename, mime, text, len(text), True, method=f"{kind}_xml")
    except Exception as exc:
        logger.warning("%s extraction failed for %s: %s", kind.upper(), filename, exc)
        return MediaExtractionResult(
            "file", filename, mime, "", success=False,
            error=f"{kind.upper()} extraction failed: {exc}", method=f"{kind}_xml",
        )


# ── Image OCR ────────────────────────────────────────────────────────────────

def extract_text_from_image(image_bytes: bytes, filename: str = "image") -> MediaExtractionResult:
    """Extract text from an image using Tesseract OCR."""
    if not _PIL_AVAILABLE:
        return MediaExtractionResult(
            source_type="image",
            filename=filename,
            mime_type="image/*",
            extracted_text="",
            success=False,
            error="Pillow not installed — cannot process images",
            method="none"
        )

    if not _TESSERACT_AVAILABLE:
        return MediaExtractionResult(
            source_type="image",
            filename=filename,
            mime_type="image/*",
            extracted_text="",
            success=False,
            error="pytesseract not installed — OCR unavailable",
            method="none"
        )

    try:
        image = Image.open(io.BytesIO(image_bytes))
        # Convert to RGB if needed (handles RGBA, palette mode, etc.)
        if image.mode not in ("L", "RGB"):
            image = image.convert("RGB")

        text = pytesseract.image_to_string(image, lang="eng")
        text = text.strip()

        return MediaExtractionResult(
            source_type="image",
            filename=filename,
            mime_type="image/*",
            extracted_text=text,
            char_count=len(text),
            success=True,
            method="tesseract_ocr"
        )
    except Exception as e:
        logger.error(f"Image OCR failed for {filename}: {e}")
        return MediaExtractionResult(
            source_type="image",
            filename=filename,
            mime_type="image/*",
            extracted_text="",
            success=False,
            error=f"OCR failed: {str(e)}",
            method="tesseract_ocr"
        )


# ── Document Text Extraction ─────────────────────────────────────────────────

def _ocr_pdf_page(page):
    """Return OCR text and word boxes for one PyMuPDF page."""
    if not (_PYMUPDF_AVAILABLE and _PIL_AVAILABLE and _TESSERACT_AVAILABLE):
        return "", []
    pixmap = page.get_pixmap(matrix=fitz.Matrix(2, 2), alpha=False)
    image = Image.open(io.BytesIO(pixmap.tobytes("png"))).convert("RGB")
    data = pytesseract.image_to_data(image, lang="eng", output_type=pytesseract.Output.DICT)
    words = []
    for index, value in enumerate(data.get("text", [])):
        value = (value or "").strip()
        if not value:
            continue
        x0 = data["left"][index] * page.rect.width / pixmap.width
        y0 = data["top"][index] * page.rect.height / pixmap.height
        x1 = (data["left"][index] + data["width"][index]) * page.rect.width / pixmap.width
        y1 = (data["top"][index] + data["height"][index]) * page.rect.height / pixmap.height
        words.append((value, fitz.Rect(x0, y0, x1, y1)))
    return " ".join(word for word, _ in words), words


def _ocr_match_rects(words, snippet):
    """Locate OCR word boxes overlapping a compact detector snippet."""
    needle = re.sub(r"\s+", "", (snippet or "")).casefold()
    if not needle:
        return []
    compact = []
    char_boxes = []
    for word, rect in words:
        for char in word:
            if char.isspace():
                continue
            compact.append(char.casefold())
            char_boxes.append(rect)
    text = "".join(compact)
    spans = []
    start = 0
    while True:
        index = text.find(needle, start)
        if index < 0:
            break
        spans.append((index, index + len(needle)))
        start = index + len(needle)
    boxes = []
    for start, end in spans:
        for rect in char_boxes[start:end]:
            if not boxes or rect not in boxes:
                boxes.append(rect)
    return boxes

def extract_text_from_pdf(file_bytes: bytes, filename: str = "document.pdf") -> MediaExtractionResult:
    """Extract selectable PDF text, using OCR for scanned pages when needed."""
    if not _PYPDF2_AVAILABLE:
        return MediaExtractionResult(
            source_type="file",
            filename=filename,
            mime_type="application/pdf",
            extracted_text="",
            success=False,
            error="PyPDF2 not installed — PDF extraction disabled",
            method="none"
        )

    try:
        reader = PdfReader(io.BytesIO(file_bytes))
        pages_text = []
        for page in reader.pages:
            page_text = page.extract_text()
            if page_text and page_text.strip():
                pages_text.append(page_text)
        text = "\n".join(pages_text).strip()

        method = "pypdf2"
        # Scanned PDFs often contain only page images. OCR pages which have no
        # selectable text so they do not silently pass inspection as empty.
        if len(pages_text) < len(reader.pages):
            if not (_PYMUPDF_AVAILABLE and _PIL_AVAILABLE and _TESSERACT_AVAILABLE):
                return MediaExtractionResult(
                    source_type="file",
                    filename=filename,
                    mime_type="application/pdf",
                    extracted_text="",
                    success=False,
                    error="This PDF has pages without selectable text, but PDF OCR is unavailable",
                    method="none",
                )
            else:
                ocr_pages = []
                unreadable_image_pages = []
                pdf = fitz.open(stream=file_bytes, filetype="pdf")
                try:
                    for index, page in enumerate(pdf):
                        selectable_text = reader.pages[index].extract_text() if index < len(reader.pages) else ""
                        if selectable_text and selectable_text.strip():
                            continue
                        page_text, _ = _ocr_pdf_page(page)
                        if page_text:
                            ocr_pages.append(page_text)
                        elif page.get_images(full=True):
                            unreadable_image_pages.append(index + 1)
                finally:
                    pdf.close()
                if unreadable_image_pages:
                    return MediaExtractionResult(
                        source_type="file",
                        filename=filename,
                        mime_type="application/pdf",
                        extracted_text="",
                        success=False,
                        error="OCR could not read image content on page(s): " + ", ".join(map(str, unreadable_image_pages)),
                        method="tesseract_ocr",
                    )
                if ocr_pages:
                    text = "\n".join(part for part in (text, *ocr_pages) if part).strip()
                    method = "pypdf2+tesseract_ocr"
                elif not text:
                    return MediaExtractionResult(
                        source_type="file",
                        filename=filename,
                        mime_type="application/pdf",
                        extracted_text="",
                        success=False,
                        error="No readable text could be extracted from this PDF",
                        method="tesseract_ocr",
                    )

        return MediaExtractionResult(
            source_type="file",
            filename=filename,
            mime_type="application/pdf",
            extracted_text=text,
            char_count=len(text),
            success=True,
            method=method
        )
    except Exception as e:
        logger.error(f"PDF extraction failed for {filename}: {e}")
        return MediaExtractionResult(
            source_type="file",
            filename=filename,
            mime_type="application/pdf",
            extracted_text="",
            success=False,
            error=f"PDF extraction failed: {str(e)}",
            method="pypdf2"
        )


def extract_text_from_docx(file_bytes: bytes, filename: str = "document.docx") -> MediaExtractionResult:
    """Extract text from a DOCX file."""
    if not _DOCX_AVAILABLE:
        return MediaExtractionResult(
            source_type="file",
            filename=filename,
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            extracted_text="",
            success=False,
            error="python-docx not installed — DOCX extraction disabled",
            method="none"
        )

    try:
        doc = docx.Document(io.BytesIO(file_bytes))
        paragraphs = [p.text for p in doc.paragraphs if p.text.strip()]

        # Also extract text from tables
        for table in doc.tables:
            for row in table.rows:
                row_text = " | ".join(cell.text.strip() for cell in row.cells if cell.text.strip())
                if row_text:
                    paragraphs.append(row_text)

        text = "\n".join(paragraphs).strip()

        return MediaExtractionResult(
            source_type="file",
            filename=filename,
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            extracted_text=text,
            char_count=len(text),
            success=True,
            method="python_docx"
        )
    except Exception as e:
        logger.error(f"DOCX extraction failed for {filename}: {e}")
        return MediaExtractionResult(
            source_type="file",
            filename=filename,
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            extracted_text="",
            success=False,
            error=f"DOCX extraction failed: {str(e)}",
            method="python_docx"
        )


def extract_text_from_xlsx(file_bytes: bytes, filename: str = "spreadsheet.xlsx") -> MediaExtractionResult:
    """Extract text from an XLSX file."""
    if not _OPENPYXL_AVAILABLE:
        return MediaExtractionResult(
            source_type="file",
            filename=filename,
            mime_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            extracted_text="",
            success=False,
            error="openpyxl not installed — XLSX extraction disabled",
            method="none"
        )

    try:
        # Scan formulas as well as cached values. Secrets can be embedded in a
        # formula even when the workbook has no cached calculation result.
        wb = openpyxl.load_workbook(io.BytesIO(file_bytes), read_only=True, data_only=False)
        all_text = []
        for sheet in wb.sheetnames:
            ws = wb[sheet]
            for row in ws.iter_rows(values_only=True):
                row_values = [str(cell) for cell in row if cell is not None]
                if row_values:
                    all_text.append(" | ".join(row_values))
        wb.close()
        text = "\n".join(all_text).strip()

        return MediaExtractionResult(
            source_type="file",
            filename=filename,
            mime_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            extracted_text=text,
            char_count=len(text),
            success=True,
            method="openpyxl"
        )
    except Exception as e:
        logger.error(f"XLSX extraction failed for {filename}: {e}")
        return MediaExtractionResult(
            source_type="file",
            filename=filename,
            mime_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            extracted_text="",
            success=False,
            error=f"XLSX extraction failed: {str(e)}",
            method="openpyxl"
        )


def extract_text_from_plaintext(file_bytes: bytes, filename: str = "file.txt", mime_type: str = "text/plain") -> MediaExtractionResult:
    """Extract text from plain text files (CSV, TXT, JSON, YAML, XML, source code, etc.)."""
    try:
        encoding = "utf-16" if file_bytes.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
        text = file_bytes.decode(encoding, errors="strict").strip()
        if "\x00" in text:
            raise ValueError("binary content is not supported as plain text")
        return MediaExtractionResult(
            source_type="file",
            filename=filename,
            mime_type=mime_type,
            extracted_text=text,
            char_count=len(text),
            success=True,
            method="direct_read"
        )
    except Exception as e:
        logger.error(f"Text extraction failed for {filename}: {e}")
        return MediaExtractionResult(
            source_type="file",
            filename=filename,
            mime_type=mime_type,
            extracted_text="",
            success=False,
            error=f"Text extraction failed: {str(e)}",
            method="direct_read"
        )


# ── Main Dispatcher ──────────────────────────────────────────────────────────

def extract_from_attachment(
    content_base64: str,
    filename: str,
    mime_type: Optional[str] = None,
    max_size_bytes: int = 10 * 1024 * 1024
) -> MediaExtractionResult:
    """
    Extract text from a base64-encoded attachment.
    Routes to the appropriate extractor based on MIME type.
    """
    resolved_mime = _resolve_mime_type(filename, mime_type)

    # Bound decoding before allocating the decoded buffer. Base64 is ~4/3 the
    # input size; allow a small margin for an optional data-URI header.
    encoded = content_base64.split(",", 1)[1] if content_base64.startswith("data:") and "," in content_base64 else content_base64
    if len(encoded) > ((max_size_bytes + 2) // 3) * 4 + 16:
        return MediaExtractionResult(
            "file", filename, resolved_mime, "", success=False,
            error=f"File exceeds size limit ({max_size_bytes} bytes)", method="none",
        )
    try:
        file_bytes = _decode_base64_content(content_base64)
    except Exception as e:
        return MediaExtractionResult(
            source_type="file",
            filename=filename,
            mime_type=resolved_mime,
            extracted_text="",
            success=False,
            error=f"Base64 decode failed: {str(e)}",
            method="none"
        )

    # Check size limit
    if len(file_bytes) > max_size_bytes:
        return MediaExtractionResult(
            source_type="file",
            filename=filename,
            mime_type=resolved_mime,
            extracted_text="",
            success=False,
            error=f"File exceeds size limit ({len(file_bytes)} > {max_size_bytes} bytes)",
            method="none"
        )

    # Route to the appropriate extractor
    if resolved_mime in IMAGE_MIME_TYPES:
        result = extract_text_from_image(file_bytes, filename)
        result.mime_type = resolved_mime
        return result

    if resolved_mime == "application/pdf":
        return extract_text_from_pdf(file_bytes, filename)

    if resolved_mime == "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
        return extract_text_from_docx(file_bytes, filename)

    if resolved_mime == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
        return extract_text_from_xlsx(file_bytes, filename)

    if resolved_mime == "application/vnd.openxmlformats-officedocument.presentationml.presentation":
        return _extract_text_from_ooxml(file_bytes, filename, "pptx")

    if resolved_mime == "application/vnd.oasis.opendocument.text":
        return _extract_text_from_ooxml(file_bytes, filename, "odt")

    # Fallback: try as plain text for text/* and JSON/XML/YAML
    if resolved_mime.startswith("text/") or resolved_mime in ("application/json", "application/xml", "application/x-yaml"):
        return extract_text_from_plaintext(file_bytes, filename, resolved_mime)

    # Never interpret an unknown binary as text: replacement decoding can hide
    # that inspection did not cover the actual document contents.
    return MediaExtractionResult(
        "file", filename, resolved_mime, "", success=False,
        error=f"Unsupported file type '{resolved_mime}'. The file was not scanned.",
        method="none",
    )


def extract_from_base64_image(data_uri_or_base64: str, filename: str = "inline_image") -> MediaExtractionResult:
    """
    Extract text from a base64-encoded image (e.g., from clipboard paste or inline embedding).
    Accepts both raw base64 and data URI format.
    """
    try:
        file_bytes = _decode_base64_content(data_uri_or_base64)
    except Exception as e:
        return MediaExtractionResult(
            source_type="image",
            filename=filename,
            mime_type="image/*",
            extracted_text="",
            success=False,
            error=f"Base64 decode failed: {str(e)}",
            method="none"
        )

    return extract_text_from_image(file_bytes, filename)


def redact_image_base64(data_uri_or_base64: str, matches) -> Optional[str]:
    """Return a PNG data URI with detector-matched OCR regions painted black.

    The detector snippets are matched against Tesseract's word-level OCR output
    so the original image can retain its visual context without sending the
    detected text pixels upstream. None means pixel redaction was unavailable.
    """
    if not (_PIL_AVAILABLE and _TESSERACT_AVAILABLE) or not matches:
        return None

    try:
        image_bytes = _decode_base64_content(data_uri_or_base64)
        image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        ocr = pytesseract.image_to_data(image, lang="eng", output_type=pytesseract.Output.DICT)

        words = []
        chunks = []
        cursor = 0
        compact_cursor = 0
        compact_chunks = []
        for index, raw_word in enumerate(ocr.get("text", [])):
            word = (raw_word or "").strip()
            if not word:
                continue
            if chunks:
                cursor += 1
            start = cursor
            chunks.append(word)
            cursor += len(word)
            words.append({
                "start": start,
                "end": cursor,
                "compact_start": compact_cursor,
                "compact_end": compact_cursor + len(word),
                "left": int(ocr["left"][index]),
                "top": int(ocr["top"][index]),
                "width": int(ocr["width"][index]),
                "height": int(ocr["height"][index]),
            })
            compact_chunks.append(word)
            compact_cursor += len(word)

        recognized = " ".join(chunks)
        compact_recognized = "".join(compact_chunks).casefold()
        spans = []
        compact_spans = []
        for match in matches:
            snippet = (match.text_snippet or "").strip()
            if not snippet:
                continue
            search_from = 0
            while True:
                found_at = recognized.casefold().find(snippet.casefold(), search_from)
                if found_at < 0:
                    break
                spans.append((found_at, found_at + len(snippet)))
                search_from = found_at + max(1, len(snippet))

            # OCR can split punctuation into separate words or insert spaces
            # around it. Search a whitespace-free fallback, then map back to
            # the OCR words so redaction still covers every pixel of a finding.
            compact_snippet = "".join(snippet.split()).casefold()
            if compact_snippet:
                search_from = 0
                while True:
                    found_at = compact_recognized.find(compact_snippet, search_from)
                    if found_at < 0:
                        break
                    compact_spans.append((found_at, found_at + len(compact_snippet)))
                    search_from = found_at + max(1, len(compact_snippet))

        if not spans and not compact_spans:
            return None

        from PIL import ImageDraw
        draw = ImageDraw.Draw(image)
        padding = max(2, round(min(image.size) * 0.004))
        redacted_boxes = set()
        for start, end in spans:
            for word in words:
                if word["start"] < end and word["end"] > start:
                    box = (
                        max(0, word["left"] - padding),
                        max(0, word["top"] - padding),
                        min(image.width, word["left"] + word["width"] + padding),
                        min(image.height, word["top"] + word["height"] + padding),
                    )
                    redacted_boxes.add(box)
        for start, end in compact_spans:
            for word in words:
                if word["compact_start"] < end and word["compact_end"] > start:
                    box = (
                        max(0, word["left"] - padding),
                        max(0, word["top"] - padding),
                        min(image.width, word["left"] + word["width"] + padding),
                        min(image.height, word["top"] + word["height"] + padding),
                    )
                    redacted_boxes.add(box)

        if not redacted_boxes:
            return None
        for box in redacted_boxes:
            draw.rectangle(box, fill="black")

        output = io.BytesIO()
        image.save(output, format="PNG")
        encoded = base64.b64encode(output.getvalue()).decode("ascii")
        return f"data:image/png;base64,{encoded}"
    except Exception as exc:
        logger.warning("Image pixel redaction failed: %s", exc)
        return None


def redact_pdf_base64(data_uri_or_base64: str, matches) -> Optional[str]:
    """Redact detected PDF spans, blanking affected pages when a span cannot be located.

    Returning the original PDF after a partial redaction would leak detections.
    If the PDF's text/OCR representation does not map cleanly back to pixels,
    conservatively blank the affected page (or the whole document if the page
    cannot be identified) so callers can still offer a safe sanitized file.
    """
    if not _PYMUPDF_AVAILABLE or not matches:
        return None
    try:
        pdf_bytes = _decode_base64_content(data_uri_or_base64)
        document = fitz.open(stream=pdf_bytes, filetype="pdf")
        redactions_added = 0
        unlocated_matches = set(range(len(matches)))
        for page in document:
            ocr_words = None
            for match_index, match in enumerate(matches):
                snippet = (match.text_snippet or "").strip()
                if not snippet:
                    continue
                rects = page.search_for(snippet)
                if not rects and _PIL_AVAILABLE and _TESSERACT_AVAILABLE:
                    if ocr_words is None:
                        _, ocr_words = _ocr_pdf_page(page)
                    rects = _ocr_match_rects(ocr_words, snippet)
                for rect in rects:
                    page.add_redact_annot(rect, fill=(0, 0, 0))
                    redactions_added += 1
                    unlocated_matches.discard(match_index)

        # Some extracted/OCR snippets cannot be mapped directly to a PDF text
        # rectangle (for example, unusual font encodings or line-wrapped IDs).
        # Identify their page by normalized text and blank it; if that fails,
        # blank every page rather than returning an unsafe partial copy.
        fallback_pages = set()
        for match_index in unlocated_matches:
            snippet = "".join(ch for ch in (matches[match_index].text_snippet or "").casefold() if ch.isalnum())
            if not snippet:
                continue
            for page_index, page in enumerate(document):
                page_text = "".join(ch for ch in page.get_text("text").casefold() if ch.isalnum())
                if snippet in page_text:
                    fallback_pages.add(page_index)
        if unlocated_matches:
            if not fallback_pages:
                fallback_pages = set(range(len(document)))
            for page_index in fallback_pages:
                document[page_index].add_redact_annot(document[page_index].rect, fill=(0, 0, 0))
                redactions_added += 1

        for page in document:
            if page.first_annot:
                page.apply_redactions()
        if not redactions_added:
            document.close()
            return None
        output = document.tobytes(garbage=4, deflate=True)
        document.close()
        return "data:application/pdf;base64," + base64.b64encode(output).decode("ascii")
    except Exception as exc:
        logger.warning("PDF redaction failed: %s", exc)
        return None


def process_all_media(
    attachments: Optional[List[dict]] = None,
    max_size_bytes: int = 10 * 1024 * 1024
) -> MediaScanSummary:
    """
    Process all media attachments and return a summary with combined extracted text.

    Each attachment dict should have:
      - filename: str
      - content_base64: str
      - mime_type: Optional[str]
    """
    summary = MediaScanSummary()

    if not attachments:
        return summary

    extracted_texts = []

    for attachment in attachments:
        filename = attachment.get("filename", "unknown")
        content_b64 = attachment.get("content_base64", "")
        mime = attachment.get("mime_type")

        if not content_b64:
            summary.total_media_items += 1
            summary.files_scanned += 1
            summary.extractions.append(MediaExtractionResult(
                "file", filename, _resolve_mime_type(filename, attachment.get("mime_type")),
                "", success=False, error="Attachment content is empty; the file was not scanned.", method="none",
            ))
            continue

        result = extract_from_attachment(content_b64, filename, mime, max_size_bytes)
        summary.extractions.append(result)
        summary.total_media_items += 1

        if result.source_type == "image":
            summary.images_scanned += 1
        else:
            summary.files_scanned += 1

        if result.success and result.extracted_text:
            media_block = f"[Content from {filename}]:\n{result.extracted_text}"
            # Track each file's position so pipeline findings can be associated
            # with the original attachment rather than an unrelated file.
            result.combined_start = sum(len(block) + 2 for block in extracted_texts)
            result.combined_end = result.combined_start + len(media_block)
            extracted_texts.append(media_block)
            summary.total_text_extracted += result.char_count

    summary.combined_text = "\n\n".join(extracted_texts)
    return summary
