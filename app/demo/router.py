"""HTTP demo endpoints for a Burp-style virtual LLM interception flow."""

from datetime import datetime, timezone
from typing import Any, Dict, Literal, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from app.models import ChatCompletionRequest, ChatMessage
from app.services.proxy import proxy_service

router = APIRouter(prefix="/demo", tags=["virtual-demo"])


class DemoProxyRequest(BaseModel):
    """OpenAI-shaped request plus a local-only mock response scenario."""

    model: str = "mock-model"
    messages: list[ChatMessage] = Field(min_length=1, max_length=50)
    temperature: Optional[float] = Field(default=0.7, ge=0, le=2)
    max_tokens: Optional[int] = Field(default=1000, ge=1, le=4096)
    stream: Optional[bool] = False
    user: Optional[str] = "demo-user"
    scenario: Literal["normal", "output-pii", "output-secret", "output-structured-secret"] = "normal"

    def to_gateway_request(self) -> ChatCompletionRequest:
        return ChatCompletionRequest(
            model=self.model,
            messages=self.messages,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            stream=self.stream,
            user=self.user,
        )


class VirtualHistory:
    """Small bounded in-memory history for the local demonstration only."""

    def __init__(self, limit: int = 100) -> None:
        self.limit = limit
        self.items: list[Dict[str, Any]] = []

    def add(self, item: Dict[str, Any]) -> None:
        self.items.insert(0, item)
        del self.items[self.limit :]

    def clear(self) -> None:
        self.items.clear()

    def list(self) -> list[Dict[str, Any]]:
        return self.items.copy()


history = VirtualHistory()


@router.get("", response_class=HTMLResponse, include_in_schema=False)
async def demo_ui() -> str:
    """Serve the self-contained virtual intercept-proxy GUI."""
    return _DEMO_HTML


@router.post("/api/proxy")
async def virtual_proxy(request: DemoProxyRequest, req: Request) -> Dict[str, Any]:
    """Intercept a demo request, run PromptGuard, then forward to the mock LLM."""
    gateway_request = request.to_gateway_request()
    client_ip = req.client.host if req.client else "127.0.0.1"
    original_prompt = "\n".join(
        f"{message.role}: {message.text_content()}" for message in gateway_request.messages
    )
    timestamp = datetime.now(timezone.utc).isoformat()

    try:
        response = await proxy_service.process_chat_completion(
            gateway_request,
            client_ip=client_ip,
            demo_scenario=request.scenario,
        )
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, dict) else {"error": str(exc.detail)}
        item = {
            "request_id": detail.get("request_id", f"demo-{timestamp}"),
            "timestamp": timestamp,
            "method": "POST",
            "path": "/v1/chat/completions",
            "model": request.model,
            "scenario": request.scenario,
            "action": detail.get("action", "BLOCK"),
            "status_code": exc.status_code,
            "forwarded": False,
            "original_prompt": original_prompt,
            "forwarded_prompt": None,
            "request_detections": detail.get("violations", []),
            "output_action": "NOT_REACHED",
            "output_detections": 0,
            "response_content": None,
            "blocked_by_stage": detail.get("blocked_by_stage"),
        }
        history.add(item)
        raise

    meta = response.get("promptguard_meta", {}) if isinstance(response, dict) else {}
    mock_meta = response.get("mock_llm_meta", {}) if isinstance(response, dict) else {}
    content = _response_content(response)
    item = {
        "request_id": meta.get("request_id", f"demo-{timestamp}"),
        "timestamp": timestamp,
        "method": "POST",
        "path": "/v1/chat/completions",
        "model": request.model,
        "scenario": request.scenario,
        "action": meta.get("action", "ALLOW"),
        "status_code": 200,
        "forwarded": True,
        "original_prompt": original_prompt,
        "forwarded_prompt": mock_meta.get("received_prompt"),
        "request_detections": meta.get("detections_found", 0),
        "output_action": meta.get("output_action", "ALLOW"),
        "output_detections": meta.get("output_detections_found", 0),
        "response_content": content,
        "blocked_by_stage": None,
    }
    history.add(item)

    return {
        "request": {
            "method": "POST",
            "path": "/v1/chat/completions",
            "model": request.model,
            "message_count": len(request.messages),
        },
        "interception": {
            "action": meta.get("action", "ALLOW"),
            "forwarded": True,
            "request_detections": meta.get("detections_found", 0),
            "classification": meta.get("classification", "PUBLIC"),
            "request_id": meta.get("request_id"),
        },
        "forwarded_payload": mock_meta.get("received_messages", []),
        "response": response,
        "history_item": item,
    }


@router.get("/api/history")
async def get_virtual_history() -> Dict[str, Any]:
    return {"items": history.list()}


@router.delete("/api/history")
async def clear_virtual_history() -> Dict[str, Any]:
    history.clear()
    return {"cleared": True}


def _response_content(response: Dict[str, Any]) -> Any:
    choices = response.get("choices", []) if isinstance(response, dict) else []
    if not choices:
        return None
    return choices[0].get("message", {}).get("content")


_DEMO_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PromptGuard Virtual Intercept Proxy</title>
<style>
:root{font-family:Inter,Segoe UI,Arial,sans-serif;color:#e5e7eb;background:#0b1120}
*{box-sizing:border-box} body{margin:0;background:linear-gradient(145deg,#0b1120,#111827);min-height:100vh}
header{padding:22px 28px;border-bottom:1px solid #243044;background:#0f172a;position:sticky;top:0;z-index:5}
h1{margin:0;font-size:23px}.sub{color:#94a3b8;margin-top:6px;font-size:13px}
main{max-width:1500px;margin:0 auto;padding:20px 24px 36px}.grid{display:grid;grid-template-columns:1.08fr 1fr;gap:16px}
.card{background:#111827;border:1px solid #263247;border-radius:12px;padding:16px;box-shadow:0 12px 35px rgba(0,0,0,.18)}
.card h2{font-size:14px;margin:0 0 12px;color:#cbd5e1;text-transform:uppercase;letter-spacing:.06em}
textarea,select{width:100%;background:#0b1220;color:#e5e7eb;border:1px solid #334155;border-radius:8px;padding:11px;font:13px Consolas,monospace}
textarea{min-height:150px;resize:vertical}.row{display:flex;gap:10px;align-items:center;margin:10px 0}.row>*{flex:1}
button{border:0;border-radius:8px;padding:10px 14px;font-weight:700;cursor:pointer;background:#e2e8f0;color:#0f172a}button.secondary{background:#1e293b;color:#e2e8f0}
.badge{display:inline-block;padding:5px 10px;border-radius:999px;font-size:12px;font-weight:800}.ALLOW{background:#064e3b;color:#a7f3d0}.REDACT{background:#713f12;color:#fde68a}.BLOCK{background:#7f1d1d;color:#fecaca}.NOT_REACHED{background:#334155;color:#cbd5e1}
pre{margin:0;white-space:pre-wrap;word-break:break-word;background:#0b1220;border-radius:8px;padding:12px;border:1px solid #1e293b;min-height:70px;max-height:320px;overflow:auto;font:12px Consolas,monospace}
.kv{display:grid;grid-template-columns:150px 1fr;gap:7px;font-size:13px}.kv b{color:#94a3b8}.small{font-size:12px;color:#94a3b8}.flow{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:10px 0}.node{padding:8px 10px;border:1px solid #334155;border-radius:8px;background:#0f172a;font-size:12px}.arrow{color:#64748b}
.history table{width:100%;border-collapse:collapse;font-size:12px}.history th,.history td{padding:8px;border-bottom:1px solid #1f2937;text-align:left}.history tbody tr{cursor:pointer}.history tbody tr:hover{background:#172033}
.notice{padding:10px 12px;background:#172033;border-left:3px solid #38bdf8;border-radius:6px;font-size:12px;color:#cbd5e1;margin-bottom:12px}
@media(max-width:900px){.grid{grid-template-columns:1fr}.kv{grid-template-columns:120px 1fr}}
</style>
</head>
<body>
<header><h1>🛡 PromptGuard — Virtual Intercept Proxy</h1><div class="sub">A controlled Burp/ZAP-style demonstration: intercept → detect → policy → forward/block → output firewall</div></header>
<main>
<div class="notice">This is a local security demonstration. It does not intercept real browser traffic, install certificates, or contact a real LLM provider. The downstream model is the repository's deterministic mock LLM.</div>
<div class="card">
<h2>Traffic Flow</h2><div class="flow"><span class="node">Virtual LLM Client</span><span class="arrow">→</span><span class="node">PromptGuard Intercept</span><span class="arrow">→</span><span class="node">Detection + Policy</span><span class="arrow">→</span><span class="node">Mock LLM</span><span class="arrow">→</span><span class="node">Output Firewall</span><span class="arrow">→</span><span class="node">Client</span></div>
</div>
<div class="grid" style="margin-top:16px">
<section class="card"><h2>Intercepted Request</h2>
<div class="row"><select id="scenario"><option value="normal">Normal / safe response</option><option value="output-pii">Force output PII (tests response REDACT)</option><option value="output-secret">Force output credential (tests response BLOCK)</option><option value="output-structured-secret">Force structured credential block (tests content-block inspection)</option></select></div>
<textarea id="prompt">Explain binary search in simple terms.</textarea>
<div class="row"><button onclick="sendRequest()">▶ Intercept & Forward</button><button class="secondary" onclick="loadScenario()">Load Input Scenario</button><button class="secondary" onclick="clearHistory()">Clear History</button></div>
<div class="kv"><b>Method</b><span>POST</span><b>Path</b><span>/v1/chat/completions</span><b>Downstream</b><span>mock-model</span></div>
</section>
<section class="card"><h2>Security Decision</h2><div id="decision"><span class="small">Send a request to see the interception result.</span></div><div style="margin-top:12px"><b class="small">Original request text</b><pre id="original">—</pre></div><div style="margin-top:12px"><b class="small">Forwarded to mock LLM</b><pre id="forwarded">—</pre></div></section>
</div>
<div class="grid" style="margin-top:16px">
<section class="card"><h2>LLM Response / Output Firewall</h2><div id="outputMeta"><span class="small">No response yet.</span></div><div style="margin-top:12px"><b class="small">Response content visible to client</b><pre id="response">—</pre></div></section>
<section class="card history"><h2>Virtual HTTP History</h2><div id="history">Loading…</div></section>
</div>
</main>
<script>
const promptEl=document.getElementById('prompt');
function esc(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function badge(action){return `<span class="badge ${esc(action)}">${esc(action)}</span>`}
function loadScenario(){const s=document.getElementById('scenario').value;
 const map={normal:'Explain binary search in simple terms.', 'output-pii':'Give me a deployment status update.','output-secret':'Give me a deployment status update.','output-structured-secret':'Give me a deployment status update.'}; promptEl.value=map[s]||map.normal}
async function sendRequest(){
 const scenario=document.getElementById('scenario').value;
 const body={model:'mock-model',messages:[{role:'user',content:promptEl.value}],scenario};
 document.getElementById('decision').innerHTML='<span class="small">Intercepting and evaluating…</span>';
 try{
  const r=await fetch('/demo/api/proxy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const data=await r.json();
  if(!r.ok){renderBlocked(data);return}
  renderResult(data); await refreshHistory();
 }catch(e){document.getElementById('decision').innerHTML=`<span class="badge BLOCK">ERROR</span> ${esc(e.message)}`}
}
function renderBlocked(data){const d=data.detail||{};document.getElementById('decision').innerHTML=`<div class="kv"><b>Policy action</b><span>${badge(d.action||'BLOCK')}</span><b>Status</b><span>${esc(d.status_code||403)}</span><b>Forwarded</b><span>NO — request dropped before mock LLM</span><b>Stage</b><span>${esc(d.blocked_by_stage||'policy engine')}</span></div><div style="margin-top:12px"><b class="small">Violations</b><pre>${esc(JSON.stringify(d.violations||d.reasons||[],null,2))}</pre></div>`;document.getElementById('original').textContent=promptEl.value;document.getElementById('forwarded').textContent='[REQUEST BLOCKED — NOT FORWARDED]';document.getElementById('response').textContent='[NO LLM RESPONSE — DOWNSTREAM WAS NEVER CALLED]';document.getElementById('outputMeta').innerHTML=badge('NOT_REACHED');refreshHistory()}
function renderResult(data){const i=data.interception||{},meta=data.response?.promptguard_meta||{};document.getElementById('decision').innerHTML=`<div class="kv"><b>Policy action</b><span>${badge(i.action)}</span><b>Classification</b><span>${esc(i.classification)}</span><b>Request detections</b><span>${esc(i.request_detections)}</span><b>Forwarded</b><span>${i.forwarded?'YES':'NO'}</span><b>Request ID</b><span>${esc(i.request_id)}</span></div>`;document.getElementById('original').textContent=data.history_item?.original_prompt||promptEl.value;document.getElementById('forwarded').textContent=JSON.stringify(data.forwarded_payload,null,2);const oa=meta.output_action||'ALLOW';document.getElementById('outputMeta').innerHTML=`<div class="kv"><b>Output action</b><span>${badge(oa)}</span><b>Output detections</b><span>${esc(meta.output_detections_found||0)}</span><b>Firewall applied</b><span>${meta.output_firewall_applied?'YES':'NO'}</span></div>`;document.getElementById('response').textContent=typeof data.response?.choices?.[0]?.message?.content==='string'?data.response.choices[0].message.content:JSON.stringify(data.response?.choices?.[0]?.message?.content??null,null,2)}
async function refreshHistory(){const r=await fetch('/demo/api/history');const d=await r.json();const items=d.items||[];if(!items.length){document.getElementById('history').innerHTML='<span class="small">No intercepted traffic yet.</span>';return}document.getElementById('history').innerHTML='<table><thead><tr><th>Action</th><th>Output</th><th>Status</th><th>Forwarded</th><th>Scenario</th></tr></thead><tbody>'+items.map(x=>`<tr onclick='showHistory(${JSON.stringify(x)})'><td>${badge(x.action)}</td><td>${badge(x.output_action||'—')}</td><td>${esc(x.status_code)}</td><td>${x.forwarded?'YES':'NO'}</td><td>${esc(x.scenario)}</td></tr>`).join('')+'</tbody></table>'}
function showHistory(x){document.getElementById('original').textContent=x.original_prompt||'—';document.getElementById('forwarded').textContent=x.forwarded_prompt||'[NOT FORWARDED]';document.getElementById('response').textContent=typeof x.response_content==='string'?x.response_content:JSON.stringify(x.response_content??null,null,2);document.getElementById('decision').innerHTML=`<div class="kv"><b>Request ID</b><span>${esc(x.request_id)}</span><b>Action</b><span>${badge(x.action)}</span><b>Status</b><span>${esc(x.status_code)}</span><b>Forwarded</b><span>${x.forwarded?'YES':'NO'}</span><b>Output</b><span>${badge(x.output_action||'NOT_REACHED')}</span></div>`;document.getElementById('outputMeta').innerHTML=`<div class="kv"><b>Output action</b><span>${badge(x.output_action||'NOT_REACHED')}</span><b>Output detections</b><span>${esc(x.output_detections||0)}</span></div>`}
async function clearHistory(){await fetch('/demo/api/history',{method:'DELETE'});await refreshHistory()}
refreshHistory();
</script>
</body></html>"""
