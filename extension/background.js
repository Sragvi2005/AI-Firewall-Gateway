/**
 * PromptGuard extension service worker.
 * Performs gateway requests from the extension origin so LLM page CSP and
 * CORS policies cannot prevent prompt inspection.
 */
'use strict';

const GATEWAY_URL = 'http://localhost:8000';

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type !== 'PROMPTGUARD_INSPECT') return false;

  const prompt = typeof message.prompt === 'string' ? message.prompt : '';
  const attachments = Array.isArray(message.attachments) ? message.attachments : [];
  const payload = {
    prompt,
    user: 'chrome-extension-user',
    ...(attachments.length ? { attachments } : {}),
  };

  fetch(`${GATEWAY_URL}/api/inspect`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
    .then((response) => {
      if (!response.ok) throw new Error(`Gateway returned ${response.status}`);
      return response.json();
    })
    .then(sendResponse)
    .catch((error) => {
      console.warn('[PromptGuard] Gateway inspection failed:', error.message);
      sendResponse(null);
    });

  return true;
});
