from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def setup_function():
    client.delete("/demo/api/history")


def _payload(prompt: str, scenario: str = "normal"):
    return {
        "model": "mock-model",
        "messages": [{"role": "user", "content": prompt}],
        "scenario": scenario,
    }


def test_virtual_proxy_ui_is_available():
    response = client.get("/demo")
    assert response.status_code == 200
    assert "PromptGuard — Virtual Intercept Proxy" in response.text
    assert "Intercept & Forward" in response.text


def test_virtual_proxy_allows_safe_request_and_forwards_it():
    response = client.post("/demo/api/proxy", json=_payload("Explain binary search."))

    assert response.status_code == 200
    body = response.json()
    assert body["interception"]["action"] == "ALLOW"
    assert body["interception"]["forwarded"] is True
    assert body["forwarded_payload"][0]["content"] == "Explain binary search."
    assert body["history_item"]["status_code"] == 200


def test_virtual_proxy_redacts_before_downstream_receives_prompt():
    response = client.post(
        "/demo/api/proxy",
        json=_payload("Please send updates to test@example.com."),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["interception"]["action"] == "REDACT"
    forwarded_text = body["history_item"]["forwarded_prompt"]
    assert "test@example.com" not in forwarded_text
    assert "[EMAIL_ADDRESS]" in forwarded_text


def test_virtual_proxy_blocks_before_downstream_receives_credential():
    response = client.post(
        "/demo/api/proxy",
        json=_payload("Here is my AWS key AKIAIOSFODNN7EXAMPLE."),
    )

    assert response.status_code == 403
    detail = response.json()["detail"]
    assert detail["action"] == "BLOCK"
    assert any(item["type"] == "AWS_ACCESS_KEY" for item in detail["violations"])

    history = client.get("/demo/api/history").json()["items"]
    assert history[0]["forwarded"] is False
    assert history[0]["output_action"] == "NOT_REACHED"


def test_virtual_proxy_output_firewall_blocks_synthetic_secret():
    response = client.post(
        "/demo/api/proxy",
        json=_payload("Give me a deployment status update.", "output-secret"),
    )

    assert response.status_code == 200
    body = response.json()
    meta = body["response"]["promptguard_meta"]
    assert meta["action"] == "ALLOW"
    assert meta["output_action"] == "BLOCK"
    assert meta["output_detections_found"] >= 1
    assert body["response"]["choices"][0]["finish_reason"] == "content_filter"
    assert "RESPONSE BLOCKED BY PROMPTGUARD OUTPUT FIREWALL" in body["response"]["choices"][0]["message"]["content"]


def test_virtual_proxy_output_firewall_inspects_structured_content_blocks():
    response = client.post(
        "/demo/api/proxy",
        json=_payload("Give me a deployment status update.", "output-structured-secret"),
    )

    assert response.status_code == 200
    body = response.json()
    meta = body["response"]["promptguard_meta"]
    assert meta["output_action"] == "BLOCK"
    assert meta["output_detections_found"] >= 1
    assert body["response"]["choices"][0]["message"]["content"].startswith(
        "[RESPONSE BLOCKED BY PROMPTGUARD OUTPUT FIREWALL:"
    )


def test_virtual_proxy_history_clear_is_deterministic():
    client.post("/demo/api/proxy", json=_payload("Explain HTTP."))
    assert client.get("/demo/api/history").json()["items"]

    response = client.delete("/demo/api/history")
    assert response.status_code == 200
    assert response.json() == {"cleared": True}
    assert client.get("/demo/api/history").json()["items"] == []
