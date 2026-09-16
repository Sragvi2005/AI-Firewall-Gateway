/**
 * PromptGuard — Chrome Extension Content Script
 *
 * Injected into ChatGPT (chatgpt.com / chat.openai.com) and Claude (claude.ai).
 * Intercepts prompt submissions, sends them to the local PromptGuard gateway
 * (http://localhost:8000) for 4-stage pipeline inspection, and shows an inline
 * security overlay with the verdict (ALLOW / REDACT / BLOCK).
 */

(function () {
  'use strict';

  const GATEWAY_URL = 'http://localhost:8000';
  const INSPECT_ENDPOINT = `${GATEWAY_URL}/api/inspect`;
  const STORAGE_KEY = 'promptguard_enabled';

  let isEnabled = true;
  let isProcessing = false;
  let overlayEl = null;

  // Load saved state
  chrome.storage?.local?.get([STORAGE_KEY], (result) => {
    isEnabled = result[STORAGE_KEY] !== false;
  });

  // Listen for toggle messages from popup
  chrome.runtime?.onMessage?.addListener((msg) => {
    if (msg.type === 'TOGGLE_PROMPTGUARD') {
      isEnabled = msg.enabled;
    }
    if (msg.type === 'GET_STATUS') {
      chrome.runtime.sendMessage({
        type: 'STATUS_RESPONSE',
        enabled: isEnabled,
        site: detectSite(),
        processing: isProcessing,
      });
    }
  });

  /* =========================================
     SITE DETECTION
     ========================================= */

  function detectSite() {
    const host = window.location.hostname;
    if (host.includes('chatgpt.com') || host.includes('chat.openai.com')) return 'chatgpt';
    if (host.includes('claude.ai')) return 'claude';
    return 'unknown';
  }

  /* =========================================
     PROMPT EXTRACTION
     ========================================= */

  function getPromptText() {
    const site = detectSite();

    if (site === 'chatgpt') {
      // ChatGPT uses a textarea with id "prompt-textarea" or a contenteditable div
      const textarea = document.getElementById('prompt-textarea');
      if (textarea) {
        // Could be a <textarea> or a contenteditable element
        return textarea.value || textarea.innerText || textarea.textContent || '';
      }
      // Fallback: look for contenteditable in the compose area
      const editable = document.querySelector('[contenteditable="true"][data-placeholder]');
      if (editable) return editable.innerText || editable.textContent || '';
    }

    if (site === 'claude') {
      // Claude uses a contenteditable div inside a fieldset
      const editable = document.querySelector('fieldset [contenteditable="true"]')
        || document.querySelector('[contenteditable="true"].ProseMirror')
        || document.querySelector('[contenteditable="true"]');
      if (editable) return editable.innerText || editable.textContent || '';
    }

    return '';
  }

  function clearPromptInput() {
    const site = detectSite();

    if (site === 'chatgpt') {
      const textarea = document.getElementById('prompt-textarea');
      if (textarea) {
        if (textarea.tagName === 'TEXTAREA') {
          textarea.value = '';
        } else {
          textarea.innerText = '';
        }
      }
    }
  }

  function setPromptText(text) {
    const site = detectSite();

    if (site === 'chatgpt') {
      const textarea = document.getElementById('prompt-textarea');
      if (textarea) {
        if (textarea.tagName === 'TEXTAREA') {
          const nativeSetter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set;
          nativeSetter.call(textarea, text);
          textarea.dispatchEvent(new Event('input', { bubbles: true }));
        } else {
          textarea.innerText = text;
          textarea.dispatchEvent(new Event('input', { bubbles: true }));
        }
      }
    }

    if (site === 'claude') {
      const editable = document.querySelector('fieldset [contenteditable="true"]')
        || document.querySelector('[contenteditable="true"].ProseMirror')
        || document.querySelector('[contenteditable="true"]');
      if (editable) {
        editable.innerHTML = `<p>${text}</p>`;
        editable.dispatchEvent(new Event('input', { bubbles: true }));
      }
    }
  }

  /* =========================================
     SEND BUTTON DETECTION
     ========================================= */

  function getSendButton() {
    const site = detectSite();

    if (site === 'chatgpt') {
      return document.querySelector('[data-testid="send-button"]')
        || document.querySelector('button[aria-label="Send prompt"]')
        || document.querySelector('form button[type="submit"]');
    }

    if (site === 'claude') {
      return document.querySelector('button[aria-label="Send Message"]')
        || document.querySelector('fieldset button:last-of-type');
    }

    return null;
  }

  /* =========================================
     GATEWAY INSPECTION
     ========================================= */

  async function inspectPrompt(promptText) {
    try {
      const resp = await fetch(INSPECT_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt: promptText, user: 'chrome-extension-user' }),
      });

      if (!resp.ok) {
        throw new Error(`Gateway returned ${resp.status}`);
      }

      return await resp.json();
    } catch (err) {
      console.error('[PromptGuard] Gateway inspection failed:', err);
      return null;
    }
  }

  /* =========================================
     OVERLAY UI
     ========================================= */

  function showOverlay(result, originalPrompt) {
    removeOverlay();

    const action = result.action;
    const iconMap = { ALLOW: '✅', REDACT: '🟡', BLOCK: '🔴' };
    const titleMap = {
      ALLOW: 'Prompt Approved — No Threats Detected',
      REDACT: 'Sensitive Data Detected — Prompt Sanitized',
      BLOCK: 'Security Threat Detected — Prompt Blocked',
    };
    const classMap = { ALLOW: 'pg-allow', REDACT: 'pg-redact', BLOCK: 'pg-block' };

    overlayEl = document.createElement('div');
    overlayEl.className = 'promptguard-overlay';
    overlayEl.id = 'promptguard-overlay';

    const reasons = (result.reasons || []).map((r) => `<div class="pg-reason">• ${escapeHtml(r)}</div>`).join('');

    let comparisonHtml = '';
    if (action === 'REDACT') {
      comparisonHtml = `
        <div class="pg-comparison">
          <div class="pg-compare-col">
            <div class="pg-compare-label">Original</div>
            <div class="pg-compare-text pg-original">${escapeHtml(originalPrompt)}</div>
          </div>
          <div class="pg-compare-col">
            <div class="pg-compare-label">Sanitized</div>
            <div class="pg-compare-text pg-sanitized">${escapeHtml(result.redacted_prompt)}</div>
          </div>
        </div>
      `;
    }

    let actionsHtml = '';
    if (action === 'ALLOW') {
      actionsHtml = `<button class="pg-btn pg-btn-proceed" id="pg-proceed-btn">Proceed →</button>`;
    } else if (action === 'REDACT') {
      actionsHtml = `
        <button class="pg-btn pg-btn-proceed" id="pg-proceed-redacted-btn">Send Sanitized Version →</button>
        <button class="pg-btn pg-btn-cancel" id="pg-cancel-btn">Cancel</button>
      `;
    } else {
      actionsHtml = `<button class="pg-btn pg-btn-cancel" id="pg-cancel-btn">Dismiss</button>`;
    }

    overlayEl.innerHTML = `
      <div class="pg-overlay-backdrop" id="pg-backdrop"></div>
      <div class="pg-overlay-card ${classMap[action]}">
        <div class="pg-overlay-header">
          <div class="pg-overlay-icon">${iconMap[action]}</div>
          <div>
            <div class="pg-overlay-title">${titleMap[action]}</div>
            <div class="pg-overlay-badge ${classMap[action]}">${action}</div>
          </div>
          <button class="pg-close-btn" id="pg-close-btn">✕</button>
        </div>
        <div class="pg-overlay-body">
          ${reasons}
          ${comparisonHtml}
        </div>
        <div class="pg-overlay-footer">
          ${actionsHtml}
        </div>
      </div>
    `;

    document.body.appendChild(overlayEl);

    // Bind actions
    const closeBtn = document.getElementById('pg-close-btn');
    const backdrop = document.getElementById('pg-backdrop');
    const proceedBtn = document.getElementById('pg-proceed-btn');
    const proceedRedactedBtn = document.getElementById('pg-proceed-redacted-btn');
    const cancelBtn = document.getElementById('pg-cancel-btn');

    if (closeBtn) closeBtn.addEventListener('click', removeOverlay);
    if (backdrop) backdrop.addEventListener('click', removeOverlay);
    if (cancelBtn) cancelBtn.addEventListener('click', () => {
      clearPromptInput();
      removeOverlay();
    });

    if (proceedBtn) {
      proceedBtn.addEventListener('click', () => {
        removeOverlay();
        // Re-set original text and click send
        setPromptText(originalPrompt);
        setTimeout(() => {
          clickSendButtonDirect();
        }, 200);
      });
    }

    if (proceedRedactedBtn) {
      proceedRedactedBtn.addEventListener('click', () => {
        removeOverlay();
        // Replace with redacted text and send
        setPromptText(result.redacted_prompt);
        setTimeout(() => {
          clickSendButtonDirect();
        }, 200);
      });
    }
  }

  function removeOverlay() {
    const el = document.getElementById('promptguard-overlay');
    if (el) {
      el.classList.add('pg-fade-out');
      setTimeout(() => el.remove(), 200);
    }
    overlayEl = null;
  }

  /**
   * Clicks the send button directly, bypassing our interceptor.
   * We temporarily set a flag so our listener doesn't re-intercept.
   */
  let bypassInterception = false;

  function clickSendButtonDirect() {
    bypassInterception = true;
    const sendBtn = getSendButton();
    if (sendBtn) {
      sendBtn.click();
    }
    // Also try pressing Enter on the input
    const site = detectSite();
    if (site === 'chatgpt') {
      const textarea = document.getElementById('prompt-textarea');
      if (textarea) {
        textarea.dispatchEvent(new KeyboardEvent('keydown', {
          key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true
        }));
      }
    }
    setTimeout(() => { bypassInterception = false; }, 500);
  }

  /* =========================================
     INTERCEPTION LOGIC
     ========================================= */

  async function handleInterception(e) {
    if (!isEnabled || isProcessing || bypassInterception) return;

    const promptText = getPromptText().trim();
    if (!promptText) return;

    // Prevent original submission
    e.preventDefault();
    e.stopPropagation();
    e.stopImmediatePropagation();

    isProcessing = true;

    // Show analyzing state
    showAnalyzingOverlay();

    // Inspect via gateway
    const result = await inspectPrompt(promptText);

    if (!result) {
      // Gateway offline — show warning but allow through
      removeOverlay();
      showOverlayError('Could not connect to PromptGuard gateway (localhost:8000). Prompt was not inspected.');
      isProcessing = false;
      return;
    }

    // Show result overlay
    showOverlay(result, promptText);
    isProcessing = false;
  }

  function showAnalyzingOverlay() {
    removeOverlay();

    overlayEl = document.createElement('div');
    overlayEl.className = 'promptguard-overlay';
    overlayEl.id = 'promptguard-overlay';

    overlayEl.innerHTML = `
      <div class="pg-overlay-backdrop"></div>
      <div class="pg-overlay-card pg-analyzing">
        <div class="pg-overlay-header">
          <div class="pg-overlay-icon">🛡️</div>
          <div>
            <div class="pg-overlay-title">Analyzing Prompt...</div>
            <div class="pg-overlay-subtitle">Running 4-stage security pipeline</div>
          </div>
        </div>
        <div class="pg-overlay-body" style="text-align: center; padding: 24px;">
          <div class="pg-spinner"></div>
          <div style="margin-top: 12px; color: #9ba3b5; font-size: 12px;">
            PII · Credentials · Financial · Intent AI
          </div>
        </div>
      </div>
    `;

    document.body.appendChild(overlayEl);
  }

  function showOverlayError(message) {
    removeOverlay();

    overlayEl = document.createElement('div');
    overlayEl.className = 'promptguard-overlay';
    overlayEl.id = 'promptguard-overlay';

    overlayEl.innerHTML = `
      <div class="pg-overlay-backdrop" id="pg-backdrop"></div>
      <div class="pg-overlay-card pg-block">
        <div class="pg-overlay-header">
          <div class="pg-overlay-icon">⚠️</div>
          <div>
            <div class="pg-overlay-title">Gateway Connection Error</div>
          </div>
          <button class="pg-close-btn" id="pg-close-btn">✕</button>
        </div>
        <div class="pg-overlay-body">
          <div class="pg-reason">${escapeHtml(message)}</div>
        </div>
        <div class="pg-overlay-footer">
          <button class="pg-btn pg-btn-cancel" id="pg-cancel-btn">Dismiss</button>
        </div>
      </div>
    `;

    document.body.appendChild(overlayEl);

    document.getElementById('pg-close-btn')?.addEventListener('click', removeOverlay);
    document.getElementById('pg-backdrop')?.addEventListener('click', removeOverlay);
    document.getElementById('pg-cancel-btn')?.addEventListener('click', removeOverlay);
  }

  /* =========================================
     EVENT LISTENERS SETUP
     ========================================= */

  function attachListeners() {
    // Intercept send button clicks
    document.addEventListener('click', (e) => {
      if (!isEnabled || isProcessing || bypassInterception) return;

      const sendBtn = getSendButton();
      if (sendBtn && (e.target === sendBtn || sendBtn.contains(e.target))) {
        const promptText = getPromptText().trim();
        if (promptText) {
          handleInterception(e);
        }
      }
    }, true); // Use capture phase to intercept before the site's handlers

    // Intercept Enter key in input
    document.addEventListener('keydown', (e) => {
      if (!isEnabled || isProcessing || bypassInterception) return;
      if (e.key !== 'Enter' || e.shiftKey) return;

      const site = detectSite();
      let isInPromptInput = false;

      if (site === 'chatgpt') {
        const textarea = document.getElementById('prompt-textarea');
        const editable = document.querySelector('[contenteditable="true"][data-placeholder]');
        isInPromptInput = (textarea && textarea.contains(e.target)) || (editable && editable.contains(e.target));
      }

      if (site === 'claude') {
        const editable = document.querySelector('fieldset [contenteditable="true"]')
          || document.querySelector('[contenteditable="true"].ProseMirror');
        isInPromptInput = editable && editable.contains(e.target);
      }

      if (isInPromptInput) {
        const promptText = getPromptText().trim();
        if (promptText) {
          handleInterception(e);
        }
      }
    }, true);
  }

  /* =========================================
     UTILITIES
     ========================================= */

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text || '';
    return div.innerHTML;
  }

  /* =========================================
     INITIALIZATION
     ========================================= */

  function init() {
    const site = detectSite();
    if (site === 'unknown') return;

    console.log(`[PromptGuard] Content script loaded on ${site}`);
    attachListeners();
  }

  // Wait for page to be ready
  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    init();
  } else {
    document.addEventListener('DOMContentLoaded', init);
  }
})();
