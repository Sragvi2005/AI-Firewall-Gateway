# PromptGuard Network Interception Proxy

PromptGuard also provides a Burp Suite-style HTTPS interception layer using `mitmproxy`.

## Architecture

```text
LLM GUI / SDK / desktop app
          |
          | HTTP(S) proxy = 127.0.0.1:8080
          v
+-----------------------------+
| PromptGuard mitmproxy addon |
|                             |
|  decrypt HTTPS with trusted |
|  local mitmproxy CA         |
+--------------+--------------+
               |
               v
      Detection Pipeline
      PII / Credentials /
      Financial / Intent /
      GLiNER
               |
               v
        Policy Engine
        ALLOW/REDACT/BLOCK
          |       |
       REDACT   BLOCK
          |       X
          v
       LLM API
          |
          v
   Output Firewall
          |
          v
        Client
```

The network proxy is different from the FastAPI reverse-proxy endpoint. The FastAPI gateway is an application-aware reverse proxy at `/v1/chat/completions`; the mitmproxy layer is a forward proxy that can sit in front of an existing LLM GUI or SDK without changing that application's endpoint.

## Why mitmproxy

The current mitmproxy documentation recommends **regular proxy mode** as the simplest and most robust mode when the client can be configured to use an HTTP proxy. By default it listens on port `8080`. HTTPS inspection requires installing and trusting mitmproxy's generated CA certificate. Addons receive the fully-read HTTP request/response and can modify the flow before forwarding it. See the official documentation:

- https://docs.mitmproxy.org/stable/concepts/modes/
- https://docs.mitmproxy.org/stable/api/events/
- https://docs.mitmproxy.org/stable/addons/examples/

## Python environment

The main PromptGuard project remains Python 3.10+ compatible. Current mitmproxy 12.2.3 requires Python 3.12+, so use a separate proxy virtual environment.

### Windows PowerShell

```powershell
py -3.12 -m venv .venv-proxy
.\.venv-proxy\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements-proxy.txt
```

### Linux/macOS

```bash
python3.12 -m venv .venv-proxy
source .venv-proxy/bin/activate
python -m pip install --upgrade pip
pip install -r requirements-proxy.txt
```

## Start PromptGuard

Terminal 1 runs the normal FastAPI gateway when you want the dashboard/API available:

```powershell
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH="."
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

The mitmproxy addon imports the same detection pipeline and policy engine directly. It does **not** call `http://localhost:8000/api/inspect`, so the network interception path does not create an unnecessary HTTP hop through the gateway.

## Start the Burp-style proxy

Terminal 2:

```powershell
.\.venv-proxy\Scripts\Activate.ps1
$env:PYTHONPATH="."
mitmdump -s app/proxy/mitm_addon.py --listen-host 127.0.0.1 --listen-port 8080
```

Or use the interactive UI:

```powershell
mitmweb -s app/proxy/mitm_addon.py --listen-host 127.0.0.1 --listen-port 8080
```

## Install the interception CA

With mitmproxy running, configure the client/device to use:

```text
HTTP proxy host: 127.0.0.1
HTTP proxy port: 8080
```

Then open the mitmproxy onboarding page from that client:

```text
http://mitm.it
```

Install and trust the generated CA certificate for the client. This is required for HTTPS interception. Do this only on systems and traffic you own or are authorized to inspect.

## Configure the LLM application

The easiest demonstration uses an application that lets you configure its HTTP(S) proxy or honors `HTTP_PROXY`/`HTTPS_PROXY`.

PowerShell example:

```powershell
$env:HTTP_PROXY="http://127.0.0.1:8080"
$env:HTTPS_PROXY="http://127.0.0.1:8080"
```

Then launch the LLM client from the same terminal.

For an application with explicit proxy settings, set both HTTP and HTTPS proxy to `127.0.0.1:8080`.

## What the addon intercepts

By default the addon inspects JSON requests sent to:

```text
api.openai.com
api.anthropic.com
api.groq.com
```

Override with:

```powershell
$env:PROMPTGUARD_PROXY_INTERCEPT_HOSTS="api.openai.com,api.yourcompany.com"
```

Use `*` only when you intentionally want to inspect every JSON POST/PUT/PATCH request passing through the proxy:

```powershell
$env:PROMPTGUARD_PROXY_INTERCEPT_HOSTS="*"
```

The request transformer understands common LLM payloads containing:

```json
{
  "messages": [
    {"role": "user", "content": "My email is alice@example.com"}
  ]
}
```

and also a top-level:

```json
{"prompt": "..."}
```

It preserves non-text content blocks and rewrites only text content.

## Security behavior

### ALLOW

The original request is forwarded unchanged.

### REDACT

The sensitive text is replaced before the request is sent upstream.

Example:

```text
Before proxy:
My email is alice@example.com

After proxy:
My email is [EMAIL_ADDRESS]
```

### BLOCK

The addon creates a local HTTP 403 response. The original request is never sent to the LLM provider.

### Output firewall

The response hook inspects common `choices[].message.content` and `choices[].delta.content` response fields before the data is released to the client.

For JSON responses, a blocked assistant message is replaced with the same security marker used by the FastAPI gateway and the choice's `finish_reason` becomes `content_filter`.

## Fail-closed mode

The default is fail-closed:

```text
PROMPTGUARD_PROXY_FAIL_CLOSED=true
```

If inspection itself fails, the proxy returns a 502 rather than forwarding uninspected LLM traffic.

For a development-only fail-open configuration:

```powershell
$env:PROMPTGUARD_PROXY_FAIL_CLOSED="false"
```

## Recommended demo

1. Start the FastAPI gateway.
2. Start `mitmdump` with the PromptGuard addon.
3. Configure the LLM GUI/SDK to use `127.0.0.1:8080`.
4. Trust the mitmproxy CA.
5. Send a clean prompt and show `ALLOW` in mitmproxy.
6. Send a prompt containing an email and show `REDACT`; inspect the upstream flow to verify the email was replaced before forwarding.
7. Send a prompt-injection example and show the local `403` without an upstream request.
8. Make the upstream LLM return a sensitive value and show the output firewall replacing/blocking the response.

## Scope and limitations

This implementation intentionally targets HTTP(S) JSON-based LLM APIs first. Some desktop applications, browsers, and managed environments bypass operating-system proxy settings. Some clients also use certificate pinning or proprietary streaming/WebSocket protocols. Those cases need a different interception mode or a provider-specific adapter rather than pretending that a generic HTTP proxy can always inspect them.
