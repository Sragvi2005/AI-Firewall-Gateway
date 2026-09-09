# PromptGuard Virtual Intercept Proxy Demo

The virtual demo reproduces the security flow of an intercepting proxy such as Burp Proxy or OWASP ZAP without intercepting real browser traffic, terminating TLS, installing certificates, or contacting a real LLM provider.

## Architecture

```text
Virtual LLM Client
        |
        | POST /v1/chat/completions
        v
PromptGuard Virtual Intercept Proxy
        |
        +--> Detection Pipeline
        |      PII / Credentials / Financial / Intent / GLiNER
        |
        +--> Policy Engine
        |      ALLOW / REDACT / BLOCK
        |
        +--> Mock LLM
        |      deterministic local response
        |
        +--> Output Firewall
        |      inspect assistant response before client sees it
        |
        v
Virtual LLM Client
```

This mirrors the core intercept/modify/drop/forward model used by Burp Proxy and OWASP ZAP. Burp documents interception of HTTP requests and responses, modification before forwarding, and dropping messages so they never reach the target. ZAP similarly supports request/response breakpoints that can modify or drop traffic.

## Start the demo

From the project root:

```bash
python -m venv .venv
# activate the environment for your shell
pip install -r requirements.txt
python -m spacy download en_core_web_sm
PYTHONPATH=. uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open:

```text
http://127.0.0.1:8000/demo
```

No browser proxy configuration is needed. The demo GUI is served by the FastAPI application.

## Scenarios

### 1. Safe request — ALLOW

Prompt:

```text
Explain binary search in simple terms.
```

Expected flow:

```text
Client -> Intercept -> Detection: 0 -> ALLOW -> Mock LLM -> Output ALLOW -> Client
```

### 2. PII input — REDACT

Prompt:

```text
Please send updates to test@example.com.
```

The policy engine should replace the email before the mock LLM receives the message.

The history panel exposes both the original text and the actual forwarded text so the data-flow boundary is visible.

### 3. Credential input — BLOCK

Prompt:

```text
Here is my AWS key AKIAIOSFODNN7EXAMPLE.
```

The request is rejected before the mock LLM is called.

The history record therefore shows:

```text
Action: BLOCK
Forwarded: NO
Output firewall: NOT_REACHED
```

### 4. Synthetic output secret — response BLOCK

Select **Force output credential (tests response BLOCK)** and send a normal deployment prompt.

The input is allowed, then the deterministic mock LLM intentionally returns the synthetic AWS example key. PromptGuard's output firewall detects it and replaces the response with the output-firewall block message.

This demonstrates the second enforcement boundary:

```text
Client -> PromptGuard -> Mock LLM
                         |
                         v
                  synthetic secret
                         |
                         v
                  Output Firewall
                         |
                         X BLOCK
                         |
                         v
                       Client
```

### 5. Structured output secret — content-block inspection

Select **Force structured credential block**. The mock LLM returns an OpenAI-style `message.content` list with multiple text blocks. PromptGuard inspects each text block and blocks the response when the synthetic credential is found.

## HTTP API

### Virtual proxy request

```http
POST /demo/api/proxy
Content-Type: application/json
```

Example:

```json
{
  "model": "mock-model",
  "messages": [
    {"role": "user", "content": "Please send updates to test@example.com."}
  ],
  "scenario": "normal"
}
```

Supported demo-only scenarios:

- `normal`
- `output-pii`
- `output-secret`
- `output-structured-secret`

The `scenario` field is only used by the deterministic local mock. It is never forwarded to a live upstream provider.

### History

```http
GET /demo/api/history
DELETE /demo/api/history
```

History is intentionally in-memory and bounded to 100 entries because this feature exists only for a local demonstration.

## Important scope

This demo is a **virtual application-layer interception test harness**, not a transparent network proxy. It does not inspect arbitrary browser or desktop traffic and does not perform TLS man-in-the-middle interception.

A future real-world deployment could place a genuine explicit or transparent proxy in front of the same PromptGuard decision engine. The virtual demo keeps that networking layer out of scope so the project's detection, policy, request-rewrite, and response-firewall behavior can be tested deterministically.
