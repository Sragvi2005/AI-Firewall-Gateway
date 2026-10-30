const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync('extension/background.js', 'utf8');

function createHarness(fetchImpl) {
  let listener;
  const context = {
    chrome: { runtime: { onMessage: { addListener(callback) { listener = callback; } } } },
    fetch: fetchImpl,
    console: { warn() {} },
  };
  vm.runInNewContext(source, context);
  return (message) => new Promise((resolve) => {
    const keepChannelOpen = listener(message, {}, resolve);
    assert.equal(keepChannelOpen, true);
  });
}

test('service worker sends inspection to the gateway and returns its verdict', async () => {
  let request;
  const inspect = createHarness(async (url, init) => {
    request = { url, init };
    return { ok: true, json: async () => ({ action: 'BLOCK' }) };
  });
  const verdict = await inspect({
    type: 'PROMPTGUARD_INSPECT',
    prompt: 'test prompt',
    attachments: [{ filename: 'note.txt', content_base64: 'data:text/plain;base64,dGVzdA==', mime_type: 'text/plain' }],
  });

  assert.equal(request.url, 'http://localhost:8000/api/inspect');
  assert.equal(request.init.method, 'POST');
  assert.deepEqual(JSON.parse(request.init.body), {
    prompt: 'test prompt',
    user: 'chrome-extension-user',
    attachments: [{ filename: 'note.txt', content_base64: 'data:text/plain;base64,dGVzdA==', mime_type: 'text/plain' }],
  });
  assert.equal(verdict.action, 'BLOCK');
});

test('service worker reports gateway failures as an unavailable inspection', async () => {
  const inspect = createHarness(async () => ({ ok: false, status: 503 }));
  assert.equal(await inspect({ type: 'PROMPTGUARD_INSPECT', prompt: 'test' }), null);
});
