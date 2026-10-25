import base64
import fitz
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models import DetectionMatch, ThreatSeverity
from app.detectors.media_extractor import redact_pdf_base64
from app.services.media_redaction import collect_media_attachments, normalize_multimodal_payload
from app.config import settings


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


@pytest.mark.parametrize("part", [
    {
        "type": "inline_data",
        "inline_data": {"mime_type": "image/png", "data": "aW1hZ2U="},
    },
    {
        "type": "image",
        "source": {"type": "base64", "media_type": "image/jpeg", "data": "aW1hZ2U="},
    },
])
def test_provider_native_inline_media_is_collected_and_normalized(part):
    message = {"role": "user", "content": [part]}

    attachments = collect_media_attachments([message])
    payload = {"messages": [{"role": "user", "content": [part]}]}
    normalize_multimodal_payload(payload)

    assert len(attachments) == 1
    assert attachments[0]["content_base64"].startswith("data:image/")
    normalized_part = payload["messages"][0]["content"][0]
    assert normalized_part["type"] == "image_url"
    assert normalized_part["image_url"]["url"] == attachments[0]["content_base64"]


def test_remote_media_reference_is_not_forwarded_uninspected():
    payload = {"messages": [{
        "role": "user",
        "content": [{"type": "image_url", "image_url": {"url": "https://files.example/image.png"}}],
    }]}

    normalize_multimodal_payload(payload)

    part = payload["messages"][0]["content"][0]
    assert part["type"] == "text"
    assert "could not inspect" in part["text"]


@pytest.mark.parametrize("endpoint", ["/v1/chat/completions", "/api/chat"])
def test_gemini_native_pdf_media_is_redacted_before_provider_forward(monkeypatch, endpoint):
    pdf_data = _pdf_data_uri("Contact: alice@example.com")
    forwarded = {}

    class FakeResponse:
        status_code = 200

        @staticmethod
        def json():
            return {"candidates": [{"content": {"parts": [{"text": "ok"}]}}]}

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return None

        async def post(self, url, *, json, headers):
            forwarded["url"] = url
            forwarded["payload"] = json
            return FakeResponse()

    monkeypatch.setattr(settings, "MOCK_LLM_MODE", False)
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "test-api-key")
    monkeypatch.setattr("app.services.proxy.httpx.AsyncClient", FakeAsyncClient)
    response = client.post(
        endpoint,
        json={
            "provider": "gemini",
            "model": "gemini-2.0-flash",
            "messages": [{
                "role": "user",
                "content": [{
                    "inline_data": {
                        "mime_type": "application/pdf",
                        "data": pdf_data.split(",", 1)[1],
                    },
                }],
            }],
        },
    )

    assert response.status_code == 200
    assert "/models/gemini-2.0-flash:generateContent" in forwarded["url"]
    parts = forwarded["payload"]["contents"][0]["parts"]
    assert "alice@example.com" not in " ".join(
        part.get("text", "") for part in parts if isinstance(part, dict)
    )
    assert any("Sanitized content from PDF" in part.get("text", "") for part in parts)
