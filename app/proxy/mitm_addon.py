from __future__ import annotations

import json
import os
import time
import uuid
from typing import Any, Dict, Iterable, Set

from mitmproxy import http, ctx

from app.config import settings
from app.detectors.pipeline import detection_pipeline
from app.policy.engine import policy_engine
from app.models import PolicyAction, PolicyDecision
from app.proxy.transformer import inspect_chat_payload, inspect_llm_response


class PromptGuardMITMProxy:
    """Burp-style network firewall for LLM HTTP(S) traffic."""

    def __init__(self) -> None:
        self.intercept_hosts = self._read_hosts()
        self.fail_closed = self._read_bool("PROMPTGUARD_PROXY_FAIL_CLOSED", True)

    @staticmethod
    def _read_bool(name: str, default: bool) -> bool:
        value = os.getenv(name)
        if value is None:
            return default
        return value.strip().lower() in {"1", "true", "yes", "on"}

    @staticmethod
    def _read_hosts() -> Set[str]:
        value = os.getenv("PROMPTGUARD_PROXY_INTERCEPT_HOSTS", "api.openai.com,api.anthropic.com,api.groq.com")
        return {item.strip().lower() for item in value.split(",") if item.strip()}

    def _is_intercepted_host(self, host: str) -> bool:
        host = host.lower()
        return "*" in self.intercept_hosts or host in self.intercept_hosts

    @staticmethod
    def _json_content(flow: http.HTTPFlow) -> Dict[str, Any] | None:
        content_type = flow.request.headers.get("content-type", "").lower()
        if "application/json" not in content_type:
            return None
        try:
            value = json.loads(flow.request.get_text(strict=False))
        except (ValueError, TypeError):
            return None
        return value if isinstance(value, dict) else None

    @staticmethod
    def _inspect_text(text: str) -> PolicyDecision:
        pipeline_result = detection_pipeline.run(text)
        return policy_engine.evaluate(text, pipeline_result)

    @staticmethod
    def _error_response(status: int, message: str, request_id: str) -> http.Response:
        body = {
            "error": {
                "message": message,
                "type": "promptguard_policy_violation",
                "code": "content_filter",
                "request_id": request_id,
            }
        }
        return http.Response.make(
            status,
            json.dumps(body).encode("utf-8"),
            {"content-type": "application/json", "x-promptguard-action": "BLOCK"},
        )

    @staticmethod
    def _request_ip(flow: http.HTTPFlow) -> str:
        return flow.client_conn.address[0] if flow.client_conn and flow.client_conn.address else "unknown"

    def request(self, flow: http.HTTPFlow) -> None:
        if flow.request.method.upper() not in {"POST", "PUT", "PATCH"}:
            return
        if not self._is_intercepted_host(flow.request.host):
            return

        payload = self._json_content(flow)
        if payload is None:
            return

        request_id = str(uuid.uuid4())
        started = time.perf_counter()
        try:
            result = inspect_chat_payload(payload, self._inspect_text)
            latency_ms = (time.perf_counter() - started) * 1000

            if not result.inspected:
                return

            flow.metadata["promptguard_request_id"] = request_id
            flow.metadata["promptguard_action"] = result.action.value
            flow.metadata["promptguard_latency_ms"] = round(latency_ms, 2)

            flow.request.headers["x-promptguard-request-id"] = request_id
            flow.request.headers["x-promptguard-action"] = result.action.value

            if result.action == PolicyAction.BLOCK:
                flow.response = self._error_response(
                    403,
                    "Request blocked by PromptGuard before reaching the LLM provider.",
                    request_id,
                )
                ctx.log.info(f"PromptGuard BLOCK {flow.request.host}{flow.request.path} request_id={request_id}")
                return

            if result.action == PolicyAction.REDACT:
                flow.request.content = json.dumps(result.payload, ensure_ascii=False).encode("utf-8")
                ctx.log.info(f"PromptGuard REDACT {flow.request.host}{flow.request.path} request_id={request_id}")
            else:
                ctx.log.info(f"PromptGuard ALLOW {flow.request.host}{flow.request.path} request_id={request_id}")

        except Exception as exc:
            ctx.log.error(f"PromptGuard request inspection failed: {exc!r}")
            if self.fail_closed:
                flow.response = self._error_response(
                    502,
                    "PromptGuard inspection failed; request was not forwarded.",
                    request_id,
                )

    def response(self, flow: http.HTTPFlow) -> None:
        if not self._is_intercepted_host(flow.request.host):
            return
        if flow.response is None:
            return

        content_type = flow.response.headers.get("content-type", "").lower()
        if "application/json" not in content_type:
            return

        try:
            payload = json.loads(flow.response.get_text(strict=False))
        except (ValueError, TypeError):
            return
        if not isinstance(payload, dict):
            return

        request_id = str(flow.metadata.get("promptguard_request_id", uuid.uuid4()))
        try:
            sanitized, action, _decisions = inspect_llm_response(payload, self._inspect_text)
            flow.response.headers["x-promptguard-output-action"] = action.value
            flow.response.headers["x-promptguard-request-id"] = request_id

            if action in {PolicyAction.REDACT, PolicyAction.BLOCK}:
                flow.response.content = json.dumps(sanitized, ensure_ascii=False).encode("utf-8")
                if action == PolicyAction.BLOCK:
                    ctx.log.info(f"PromptGuard OUTPUT BLOCK {flow.request.host}{flow.request.path} request_id={request_id}")
                else:
                    ctx.log.info(f"PromptGuard OUTPUT REDACT {flow.request.host}{flow.request.path} request_id={request_id}")
        except Exception as exc:
            ctx.log.error(f"PromptGuard response inspection failed: {exc!r}")
            if self.fail_closed:
                flow.response = self._error_response(
                    502,
                    "PromptGuard output inspection failed; response was not released.",
                    request_id,
                )


addons = [PromptGuardMITMProxy()]
