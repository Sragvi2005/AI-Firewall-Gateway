const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync('extension/fetch_interceptor.js', 'utf8');

class FakeFileReader {
  readAsDataURL(blob) {
    blob.arrayBuffer().then((buffer) => {
      this.result = `data:${blob.type || 'application/octet-stream'};base64,${Buffer.from(buffer).toString('base64')}`;
      this.onload();
    }).catch((error) => {
      this.error = error;
      this.onerror();
    });
  }
}

function createHarness(inspectResult) {
  const state = { inspected: null, forwarded: null };
  const listeners = new Map();
  const window = {
    addEventListener(type, listener) {
      if (!listeners.has(type)) listeners.set(type, new Set());
      listeners.get(type).add(listener);
    },
    removeEventListener(type, listener) {
      listeners.get(type)?.delete(listener);
    },
    postMessage(message) {
      if (message.type !== '__promptguard_inspect_request') return;
      state.inspected = {
        prompt: message.prompt,
        user: 'chrome-extension-user',
        ...(message.attachments.length ? { attachments: message.attachments } : {}),
      };
      for (const listener of listeners.get('message') || []) {
        listener({ source: window, data: {
          type: '__promptguard_inspect_response',
          requestId: message.requestId,
          result: inspectResult,
        } });
      }
    },
    dispatchEvent() {},
    fetch: async (resource, init = {}) => {
      state.forwarded = { resource: String(resource), init };
      return { ok: true, status: 200 };
    },
  };
  class FakeXMLHttpRequest {}
  const context = {
    window,
    FormData,
    Blob,
    File,
    FileReader: FakeFileReader,
    Headers,
    Request,
    Response,
    XMLHttpRequest: FakeXMLHttpRequest,
    CustomEvent: class CustomEvent { constructor(type, options) { this.type = type; this.detail = options?.detail; } },
    TextDecoder,
    Uint8Array,
    Date,
    setTimeout,
    clearTimeout,
    atob,
    btoa,
    console: { log() {}, warn() {}, error() {} },
  };
  vm.runInNewContext(source, context);
  return { state, fetch: window.fetch };
}

test('Gemini multipart media is inspected and replaced before fetch', async () => {
  const safePdf = Buffer.from('%PDF sanitized copy').toString('base64');
  const result = {
    action: 'REDACT',
    redacted_prompt: 'Summarize [EMAIL_ADDRESS]',
    reasons: ['Sensitive data found in media'],
    media_redaction_failures: [],
    pipeline: {
      media_scan: { extractions: [{ filename: 'report.pdf', success: true }] },
      stage_results: [{ matches: [{ source: 'media:report.pdf' }] }],
    },
    sanitized_attachments: [{
      filename: 'report.pdf',
      mime_type: 'application/pdf',
      content_base64: `data:application/pdf;base64,${safePdf}`,
    }],
  };
  const harness = createHarness(result);
  const body = new FormData();
  body.append('prompt', 'Summarize this file alice@example.com');
  body.append('file', new File([Buffer.from('%PDF original with alice@example.com')], 'report.pdf', { type: 'application/pdf' }));

  await harness.fetch('https://gemini.google.com/_/generate', {
    method: 'POST',
    headers: new Headers({ 'Content-Type': 'multipart/form-data; boundary=old-boundary' }),
    body,
  });

  assert.equal(harness.state.inspected.attachments.length, 1);
  assert.equal(harness.state.inspected.attachments[0].filename, 'report.pdf');
  const outgoing = harness.state.forwarded.init.body;
  assert.equal(outgoing instanceof FormData, true);
  assert.equal(outgoing.get('prompt'), 'Summarize [EMAIL_ADDRESS]');
  assert.equal(await outgoing.get('file').text(), '%PDF sanitized copy');
  assert.equal(harness.state.forwarded.init.headers.has('content-type'), false);
});
