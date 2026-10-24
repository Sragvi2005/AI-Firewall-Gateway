import base64
import fitz
from fastapi.testclient import TestClient

from app.main import app
from app.models import DetectionMatch, ThreatSeverity
from app.detectors.media_extractor import redact_pdf_base64


client = TestClient(app)


def _pdf_data_uri(text: str) -> str:
    document = fitz.open()
    page = document.new_page()
    page.insert_text((72, 100), text)
    pdf_bytes = document.tobytes()
    document.close()
    return "data:application/pdf;base64," + base64.b64encode(pdf_bytes).decode("ascii")


def test_pdf_redaction_returns_safe_copy_when_detector_span_cannot_be_located():
    original = _pdf_data_uri("Keep this page safe: alice@example.com")
    match = DetectionMatch(
        stage_id=1,
        stage_name="PII Detection",
        entity_type="EMAIL_ADDRESS",
        text_snippet="a detector span that cannot be mapped",
        start=0,
        end=1,
        confidence=1.0,
        severity=ThreatSeverity.HIGH,
        description="Sensitive data detected",
        source="media:application.pdf",
    )

    sanitized = redact_pdf_base64(original, [match])

    assert sanitized and sanitized.startswith("data:application/pdf;base64,")
    pdf_bytes = base64.b64decode(sanitized.split(",", 1)[1])
    document = fitz.open(stream=pdf_bytes, filetype="pdf")
    assert document.page_count == 1
    assert "alice@example.com" not in document[0].get_text()
    document.close()


def test_inspect_endpoint_returns_downloadable_sanitized_pdf():
    pdf_data = _pdf_data_uri("Application contact: alice@example.com")
    response = client.post(
        "/api/inspect",
        json={
            "prompt": "Please review my application.",
            "attachments": [{
                "filename": "application.pdf",
                "content_base64": pdf_data,
                "mime_type": "application/pdf",
            }],
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert result["action"] == "REDACT"
    sanitized = next(
        item for item in result["sanitized_attachments"]
        if item["filename"] == "application.pdf"
    )
    assert sanitized["content_base64"].startswith("data:application/pdf;base64,")
    clean_bytes = base64.b64decode(sanitized["content_base64"].split(",", 1)[1])
    document = fitz.open(stream=clean_bytes, filetype="pdf")
    assert all("alice@example.com" not in page.get_text() for page in document)
    document.close()
