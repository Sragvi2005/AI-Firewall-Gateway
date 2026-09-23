/**
 * PromptGuard — Chrome Extension Content Script
 *
 * Injected into ChatGPT, Claude, Gemini, Mistral Le Chat, Groq, and Cohere Coral.
 * Intercepts prompt submissions, sends them to the local PromptGuard gateway
 * (http://localhost:8000) for 4-stage pipeline inspection, and shows an inline
 * security overlay with the verdict (ALLOW / REDACT / BLOCK).
 *
 * On Claude.ai this script runs in the MAIN world alongside claude_bridge.js,
 * which provides ProseMirror-compatible text read/write helpers.
 */

(function () {
  'use strict';

  const GATEWAY_URL = 'http://localhost:8000';
  const INSPECT_ENDPOINT = `${GATEWAY_URL}/api/inspect`;
  const STORAGE_KEY = 'promptguard_enabled';

  let isEnabled = true;
  let isProcessing = false;
  let overlayEl = null;
  let bypassInterception = false;
  let listenersAttached = false;
  let pendingAttachments = [];

  // Storage API may not be available in MAIN world — wrap safely
  try {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get([STORAGE_KEY], (result) => {
        isEnabled = result[STORAGE_KEY] !== false;
      });
    }
  } catch (e) { /* MAIN world — no chrome.storage access */ }

  // Listen for toggle messages from popup
  try {
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
      chrome.runtime.onMessage.addListener((msg) => {
        if (msg.type === 'TOGGLE_PROGUARD' || msg.type === 'TOGGLE_PROMPTGUARD') {
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
    }
  } catch (e) { /* MAIN world — no chrome.runtime access */ }

  // In MAIN world, listen for toggle via custom DOM events
  window.addEventListener('promptguard-toggle', (e) => {
    if (e.detail && typeof e.detail.enabled === 'boolean') {
      isEnabled = e.detail.enabled;
    }
  });

  /* =========================================
     MEDIA & ATTACHMENT CAPTURE
     ========================================= */

  function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  function readFileAsBase64(file) {
    return new Promise((resolve) => {
      if (!file) return resolve(null);
      // Safety limit: 25MB
      if (file.size > 25 * 1024 * 1024) {
        console.warn(`[PromptGuard] File "${file.name}" exceeds 25MB limit, skipping base64 encoding.`);
        return resolve(null);
      }
      const reader = new FileReader();
      reader.onload = () => {
        resolve({
          filename: file.name || 'unnamed_attachment',
          content_base64: reader.result, // "data:image/png;base64,..."
          mime_type: file.type || 'application/octet-stream',
          size: file.size || 0,
          timestamp: Date.now(),
        });
      };
      reader.onerror = (err) => {
        console.warn(`[PromptGuard] Error reading file "${file.name}":`, err);
        resolve(null);
      };
      reader.readAsDataURL(file);
    });
  }

  async function addFiles(fileList) {
    if (!fileList || fileList.length === 0) return;
    const promises = [];
    for (let i = 0; i < fileList.length; i++) {
      const file = fileList[i];
      if (file && typeof file === 'object') {
        // Prevent duplicate file entries by filename & size
        const exists = pendingAttachments.some(
          (a) => a.filename === file.name && a.size === file.size
        );
        if (!exists) {
          promises.push(readFileAsBase64(file));
        }
      }
    }
    const results = await Promise.all(promises);
    for (const res of results) {
      if (res && res.content_base64) {
        pendingAttachments.push(res);
        console.log(`[PromptGuard] Captured file attachment: ${res.filename} (${formatBytes(res.size)}, ${res.mime_type})`);
      }
    }
  }

  function getActiveAttachments() {
    // Prune attachments older than 15 minutes
    const cutoff = Date.now() - 15 * 60 * 1000;
    pendingAttachments = pendingAttachments.filter((a) => a.timestamp > cutoff);
    return [...pendingAttachments];
  }

  function clearAttachments() {
    pendingAttachments = [];
  }


  /* =========================================
     SITE DETECTION
     ========================================= */

  function detectSite() {
    const host = window.location.hostname;
    if (host.includes('chatgpt.com') || host.includes('chat.openai.com')) return 'chatgpt';
    if (host.includes('claude.ai')) return 'claude';
    if (host.includes('gemini.google.com')) return 'gemini';
    if (host.includes('chat.mistral.ai')) return 'mistral';
    if (host.includes('groq.com')) return 'groq';
    if (host.includes('coral.cohere.com')) return 'cohere';
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
        return textarea.value || textarea.innerText || textarea.textContent || '';
      }
      // Fallback: look for contenteditable in the compose area
      const editable = document.querySelector('[contenteditable="true"][data-placeholder]');
      if (editable) return editable.innerText || editable.textContent || '';
    }

    if (site === 'claude') {
      // Use the Claude bridge if available (MAIN world)
      if (window.__promptguard_claude) {
        return window.__promptguard_claude.getText();
      }
      // Fallback: direct DOM query with broad selectors
      const selectors = [
        '.ProseMirror[contenteditable="true"]',
        '[data-placeholder][contenteditable="true"]',
        '[role="textbox"][contenteditable="true"]',
        'fieldset [contenteditable="true"]',
        '[contenteditable="true"]',
      ];
      for (const sel of selectors) {
        const el = document.querySelector(sel);
        if (el) {
          const text = el.innerText || el.textContent || '';
          if (text.trim()) return text;
        }
      }
    }

    if (site === 'gemini') {
      // Gemini uses a rich text editor with contenteditable
      const selectors = [
        '.ql-editor[contenteditable="true"]',
        '[contenteditable="true"][aria-label*="prompt"]',
        '[contenteditable="true"][aria-label*="Enter"]',
        '.text-input-field [contenteditable="true"]',
        'rich-textarea [contenteditable="true"]',
        '[contenteditable="true"]',
      ];
      for (const sel of selectors) {
        const el = document.querySelector(sel);
        if (el) {
          const text = el.innerText || el.textContent || '';
          if (text.trim()) return text;
        }
      }
    }

    if (site === 'mistral') {
      // Mistral Le Chat uses a textarea or contenteditable
      const selectors = [
        'textarea[placeholder]',
        '[contenteditable="true"][role="textbox"]',
        '[contenteditable="true"]',
      ];
      for (const sel of selectors) {
        const el = document.querySelector(sel);
        if (el) {
          const text = el.value || el.innerText || el.textContent || '';
          if (text.trim()) return text;
        }
      }
    }

    if (site === 'groq') {
      // Groq uses a textarea
      const selectors = [
        'textarea[placeholder]',
        '#chat-input',
        'textarea',
      ];
      for (const sel of selectors) {
        const el = document.querySelector(sel);
        if (el) {
          const text = el.value || el.innerText || '';
          if (text.trim()) return text;
        }
      }
    }

    if (site === 'cohere') {
      // Cohere Coral uses a textarea or contenteditable
      const selectors = [
        'textarea[placeholder]',
        '[contenteditable="true"][role="textbox"]',
        '[contenteditable="true"]',
        'textarea',
      ];
      for (const sel of selectors) {
        const el = document.querySelector(sel);
        if (el) {
          const text = el.value || el.innerText || el.textContent || '';
          if (text.trim()) return text;
        }
      }
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

    if (site === 'claude' && window.__promptguard_claude) {
      window.__promptguard_claude.clear();
    }

    // Generic clear for other sites
    if (['gemini', 'mistral', 'groq', 'cohere'].includes(site)) {
      const textarea = document.querySelector('textarea');
      if (textarea) {
        const nativeSetter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')?.set;
        if (nativeSetter) {
          nativeSetter.call(textarea, '');
          textarea.dispatchEvent(new Event('input', { bubbles: true }));
        } else {
          textarea.value = '';
        }
        return;
      }
      const editable = document.querySelector('[contenteditable="true"]');
      if (editable) {
        editable.innerText = '';
        editable.dispatchEvent(new Event('input', { bubbles: true }));
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
      if (window.__promptguard_claude) {
        window.__promptguard_claude.setText(text);
      } else {
        // Fallback: direct DOM manipulation
        const editable = document.querySelector('.ProseMirror[contenteditable="true"]')
          || document.querySelector('[contenteditable="true"]');
        if (editable) {
          editable.focus();
          const sel = window.getSelection();
          const range = document.createRange();
          range.selectNodeContents(editable);
          sel.removeAllRanges();
          sel.addRange(range);
          document.execCommand('insertText', false, text);
        }
      }
    }

    // Generic set for other sites
    if (['gemini', 'mistral', 'groq', 'cohere'].includes(site)) {
      const textarea = document.querySelector('textarea');
      if (textarea) {
        const nativeSetter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')?.set;
        if (nativeSetter) {
          nativeSetter.call(textarea, text);
          textarea.dispatchEvent(new Event('input', { bubbles: true }));
        } else {
          textarea.value = text;
          textarea.dispatchEvent(new Event('input', { bubbles: true }));
        }
        return;
      }
      const editable = document.querySelector('[contenteditable="true"]');
      if (editable) {
        editable.focus();
        const sel = window.getSelection();
        const range = document.createRange();
        range.selectNodeContents(editable);
        sel.removeAllRanges();
        sel.addRange(range);
        document.execCommand('insertText', false, text);
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
      if (window.__promptguard_claude) {
        return window.__promptguard_claude.getSendButton();
      }
      // Fallback
      return document.querySelector('button[aria-label="Send Message"]')
        || document.querySelector('button[aria-label="Send message"]')
        || document.querySelector('button[aria-label="Send"]')
        || document.querySelector('fieldset button:last-of-type');
    }

    if (site === 'gemini') {
      return document.querySelector('button[aria-label="Send message"]')
        || document.querySelector('button[aria-label="Send"]')
        || document.querySelector('.send-button')
        || document.querySelector('button[mat-icon-button][aria-label*="Send"]')
        || document.querySelector('button.send-button');
    }

    if (site === 'mistral') {
      return document.querySelector('button[aria-label="Send"]')
        || document.querySelector('button[aria-label="Send message"]')
        || document.querySelector('button[type="submit"]')
        || document.querySelector('form button:last-of-type');
    }

    if (site === 'groq') {
      return document.querySelector('button[aria-label="Send"]')
        || document.querySelector('button[aria-label="Send message"]')
        || document.querySelector('button[type="submit"]')
        || document.querySelector('form button:last-of-type');
    }

    if (site === 'cohere') {
      return document.querySelector('button[aria-label="Send"]')
        || document.querySelector('button[aria-label="Send message"]')
        || document.querySelector('button[type="submit"]')
        || document.querySelector('form button:last-of-type');
    }

    return null;
  }

  /* =========================================
     GATEWAY INSPECTION
     ========================================= */

  async function inspectPrompt(promptText, attachments = []) {
    try {
      const payload = {
        prompt: promptText || '',
        user: 'chrome-extension-user',
      };
      if (attachments && attachments.length > 0) {
        payload.attachments = attachments.map((a) => ({
          filename: a.filename,
          content_base64: a.content_base64,
          mime_type: a.mime_type,
        }));
      }

      const resp = await fetch(INSPECT_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
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

  function showOverlay(result, originalPrompt, attachments = []) {
    removeOverlay();

    const action = result.action;
    const iconMap = { ALLOW: '✅', REDACT: '🟡', BLOCK: '🔴' };
    const titleMap = {
      ALLOW: 'Prompt & Media Approved — No Threats Detected',
      REDACT: 'Sensitive Data Detected — Sanitized',
      BLOCK: 'Security Threat Detected — Blocked',
    };
    const classMap = { ALLOW: 'pg-allow', REDACT: 'pg-redact', BLOCK: 'pg-block' };

    overlayEl = document.createElement('div');
    overlayEl.className = 'promptguard-overlay';
    overlayEl.id = 'promptguard-overlay';

    // Format media scanning summary badge & attachment chips if any
    const mediaScan = result.pipeline?.media_scan;
    let mediaBadgeHtml = '';
    const scannedCount = attachments.length || ((mediaScan?.images_scanned || 0) + (mediaScan?.files_scanned || 0));
    if (scannedCount > 0) {
      mediaBadgeHtml = `
        <div class="pg-media-badge">
          <span>📎</span>
          <span>${scannedCount} attachment${scannedCount > 1 ? 's' : ''} scanned (OCR & Document Parsing)</span>
        </div>
      `;
      if (attachments.length > 0) {
        mediaBadgeHtml += `
          <div class="pg-media-list">
            ${attachments.map((a) => `<span class="pg-media-chip">📄 ${escapeHtml(a.filename)} <small style="color:#64748b">(${formatBytes(a.size)})</small></span>`).join('')}
          </div>
        `;
      }
    }

    const reasons = (result.reasons || []).map((r) => {
      let sourceTag = '';
      if (r.toLowerCase().includes('media:') || r.toLowerCase().includes('attachment') || r.toLowerCase().includes('image') || r.toLowerCase().includes('file')) {
        sourceTag = `<span class="pg-source-tag pg-source-media">MEDIA</span>`;
      } else {
        sourceTag = `<span class="pg-source-tag">PROMPT</span>`;
      }
      return `<div class="pg-reason">• ${sourceTag}${escapeHtml(r)}</div>`;
    }).join('');

    let comparisonHtml = '';
    if (action === 'REDACT') {
      comparisonHtml = `
        <div class="pg-comparison">
          <div class="pg-compare-col">
            <div class="pg-compare-label">Original Prompt</div>
            <div class="pg-compare-text pg-original">${escapeHtml(originalPrompt || '(No text prompt, media attached)')}</div>
          </div>
          <div class="pg-compare-col">
            <div class="pg-compare-label">Sanitized Prompt</div>
            <div class="pg-compare-text pg-sanitized">${escapeHtml(result.redacted_prompt || '(Empty)')}</div>
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
          ${mediaBadgeHtml}
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
      clearAttachments();
      removeOverlay();
    });

    if (proceedBtn) {
      proceedBtn.addEventListener('click', () => {
        removeOverlay();
        // Re-set original text and click send
        if (originalPrompt) {
          setPromptText(originalPrompt);
        }
        setTimeout(() => {
          clickSendButtonDirect();
          clearAttachments();
        }, 300);
      });
    }

    if (proceedRedactedBtn) {
      proceedRedactedBtn.addEventListener('click', () => {
        removeOverlay();
        // Replace with redacted text and send
        setPromptText(result.redacted_prompt);
        setTimeout(() => {
          clickSendButtonDirect();
          clearAttachments();
        }, 300);
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
  function clickSendButtonDirect() {
    bypassInterception = true;
    const site = detectSite();

    if (site === 'claude' && window.__promptguard_claude) {
      window.__promptguard_claude.clickSend();
    } else {
      const sendBtn = getSendButton();
      if (sendBtn) {
        sendBtn.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
        sendBtn.dispatchEvent(new MouseEvent('mouseup', { bubbles: true }));
        sendBtn.click();
      }
      // Also try pressing Enter on the input for sites using textarea
      if (['chatgpt', 'gemini', 'mistral', 'groq', 'cohere'].includes(site)) {
        const textarea = document.querySelector('textarea')
          || document.getElementById('prompt-textarea');
        if (textarea) {
          textarea.dispatchEvent(new KeyboardEvent('keydown', {
            key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true
          }));
        }
      }
    }

    setTimeout(() => { bypassInterception = false; }, 800);
  }

  /* =========================================
     INTERCEPTION LOGIC
     ========================================= */

  async function handleInterception(e) {
    if (!isEnabled || isProcessing || bypassInterception) return;

    const promptText = getPromptText().trim();
    const attachments = getActiveAttachments();

    // If there is neither prompt text nor attachments, do not intercept
    if (!promptText && attachments.length === 0) return;

    // Prevent original submission
    e.preventDefault();
    e.stopPropagation();
    e.stopImmediatePropagation();

    isProcessing = true;

    // Show analyzing state
    showAnalyzingOverlay(attachments.length);

    // Inspect via gateway
    const result = await inspectPrompt(promptText, attachments);

    if (!result) {
      // Gateway offline — show warning but allow through
      removeOverlay();
      showOverlayError('Could not connect to PromptGuard gateway (localhost:8000). Prompt was not inspected.');
      isProcessing = false;
      return;
    }

    // Show result overlay
    showOverlay(result, promptText, attachments);
    isProcessing = false;
  }

  function showAnalyzingOverlay(attachmentCount = 0) {
    removeOverlay();

    overlayEl = document.createElement('div');
    overlayEl.className = 'promptguard-overlay';
    overlayEl.id = 'promptguard-overlay';

    const mediaSubtext = attachmentCount > 0
      ? `Analyzing prompt & ${attachmentCount} attachment${attachmentCount > 1 ? 's' : ''} (OCR + Docs)`
      : `Running 4-stage security pipeline`;

    overlayEl.innerHTML = `
      <div class="pg-overlay-backdrop"></div>
      <div class="pg-overlay-card pg-analyzing">
        <div class="pg-overlay-header">
          <div class="pg-overlay-icon">🛡️</div>
          <div>
            <div class="pg-overlay-title">Analyzing Content...</div>
            <div class="pg-overlay-subtitle">${escapeHtml(mediaSubtext)}</div>
          </div>
        </div>
        <div class="pg-overlay-body" style="text-align: center; padding: 24px;">
          <div class="pg-spinner"></div>
          <div style="margin-top: 12px; color: #9ba3b5; font-size: 12px;">
            PII · Credentials · Financial · OCR & Documents · Intent AI
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
    if (listenersAttached) return;
    listenersAttached = true;

    const site = detectSite();
    console.log(`[PromptGuard] Attaching event listeners for ${site}`);

    // Intercept file uploads via <input type="file">
    document.addEventListener('change', (e) => {
      if (e.target && (e.target.type === 'file' || e.target.tagName === 'INPUT') && e.target.files && e.target.files.length > 0) {
        addFiles(e.target.files);
      }
    }, true);

    // Intercept drag and drop files
    document.addEventListener('drop', (e) => {
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        addFiles(e.dataTransfer.files);
      }
    }, true);

    // Intercept clipboard paste of images/files
    document.addEventListener('paste', (e) => {
      if (e.clipboardData) {
        const files = [];
        if (e.clipboardData.files && e.clipboardData.files.length > 0) {
          for (let i = 0; i < e.clipboardData.files.length; i++) {
            files.push(e.clipboardData.files[i]);
          }
        } else if (e.clipboardData.items) {
          for (let i = 0; i < e.clipboardData.items.length; i++) {
            const item = e.clipboardData.items[i];
            if (item.kind === 'file') {
              const file = item.getAsFile();
              if (file) files.push(file);
            }
          }
        }
        if (files.length > 0) {
          addFiles(files);
        }
      }
    }, true);

    // Intercept send button clicks
    document.addEventListener('click', (e) => {
      if (!isEnabled || isProcessing || bypassInterception) return;

      const sendBtn = getSendButton();
      if (sendBtn && (e.target === sendBtn || sendBtn.contains(e.target))) {
        const promptText = getPromptText().trim();
        const attachments = getActiveAttachments();
        if (promptText || attachments.length > 0) {
          handleInterception(e);
        }
      }
    }, true); // Use capture phase to intercept before the site's handlers

    // Intercept Enter key in input
    document.addEventListener('keydown', (e) => {
      if (!isEnabled || isProcessing || bypassInterception) return;
      if (e.key !== 'Enter' || e.shiftKey) return;

      let isInPromptInput = false;

      if (site === 'chatgpt') {
        const textarea = document.getElementById('prompt-textarea');
        const editable = document.querySelector('[contenteditable="true"][data-placeholder]');
        isInPromptInput = (textarea && textarea.contains(e.target))
          || (editable && editable.contains(e.target));
      }

      if (site === 'claude') {
        // Broad detection: any contenteditable that's a ProseMirror or text input
        const editor = window.__promptguard_claude
          ? window.__promptguard_claude.getEditor()
          : document.querySelector('.ProseMirror[contenteditable="true"]')
            || document.querySelector('[contenteditable="true"]');
        if (editor) {
          isInPromptInput = editor.contains(e.target) || e.target === editor;
        }
      }

      if (site === 'gemini') {
        const editor = document.querySelector('.ql-editor[contenteditable="true"]')
          || document.querySelector('rich-textarea [contenteditable="true"]')
          || document.querySelector('[contenteditable="true"]');
        if (editor) {
          isInPromptInput = editor.contains(e.target) || e.target === editor;
        }
      }

      if (['mistral', 'groq', 'cohere'].includes(site)) {
        const textarea = document.querySelector('textarea');
        const editable = document.querySelector('[contenteditable="true"][role="textbox"]')
          || document.querySelector('[contenteditable="true"]');
        isInPromptInput = (textarea && textarea.contains(e.target))
          || (editable && (editable.contains(e.target) || e.target === editable));
      }

      if (isInPromptInput) {
        const promptText = getPromptText().trim();
        const attachments = getActiveAttachments();
        if (promptText || attachments.length > 0) {
          handleInterception(e);
        }
      }
    }, true);
  }


  /* =========================================
     MUTATION OBSERVER — Wait for editor UI
     ========================================= */

  function waitForEditorAndAttach() {
    const site = detectSite();

    // For ChatGPT, the textarea is usually present on load
    if (site === 'chatgpt') {
      attachListeners();
      return;
    }

    // For sites with lazy-rendered editors — use MutationObserver
    if (['claude', 'gemini', 'mistral', 'groq', 'cohere'].includes(site)) {
      const checkEditor = () => {
        if (site === 'claude') {
          const editor = window.__promptguard_claude
            ? window.__promptguard_claude.getEditor()
            : document.querySelector('[contenteditable="true"]');
          return !!editor;
        }
        // For other sites, check for textarea or contenteditable
        return !!document.querySelector('textarea')
          || !!document.querySelector('[contenteditable="true"]');
      };

      if (checkEditor()) {
        console.log(`[PromptGuard] ${site} editor found immediately`);
        attachListeners();
        return;
      }

      console.log(`[PromptGuard] Waiting for ${site} editor to appear...`);
      const observer = new MutationObserver(() => {
        if (checkEditor()) {
          console.log(`[PromptGuard] ${site} editor detected via MutationObserver`);
          observer.disconnect();
          attachListeners();
        }
      });

      observer.observe(document.body, {
        childList: true,
        subtree: true,
      });

      // Safety timeout: stop observing after 30 seconds
      setTimeout(() => {
        observer.disconnect();
        if (!listenersAttached) {
          console.warn(`[PromptGuard] Timed out waiting for ${site} editor, attaching listeners anyway`);
          attachListeners();
        }
      }, 30000);
    }
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
     INJECT CSS (for MAIN world where CSS may
     not be injected via manifest)
     ========================================= */

  function injectStyles() {
    // Check if styles are already present
    if (document.getElementById('promptguard-injected-styles')) return;

    const style = document.createElement('style');
    style.id = 'promptguard-injected-styles';
    style.textContent = `
      .promptguard-overlay {
        position: fixed;
        top: 0; left: 0; right: 0; bottom: 0;
        z-index: 2147483647;
        display: flex;
        align-items: center;
        justify-content: center;
        animation: pgFadeIn 0.2s ease;
      }
      .promptguard-overlay.pg-fade-out {
        animation: pgFadeOut 0.2s ease forwards;
      }
      .pg-overlay-backdrop {
        position: absolute;
        inset: 0;
        background: rgba(0, 0, 0, 0.55);
        backdrop-filter: blur(4px);
      }
      .pg-overlay-card {
        position: relative;
        width: 520px;
        max-width: 90vw;
        max-height: 80vh;
        overflow-y: auto;
        background: #1a1a2e;
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 16px;
        box-shadow: 0 24px 80px rgba(0,0,0,0.5);
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        color: #e8eaf0;
      }
      .pg-overlay-card.pg-allow { border-color: rgba(52, 211, 153, 0.3); }
      .pg-overlay-card.pg-redact { border-color: rgba(251, 191, 36, 0.3); }
      .pg-overlay-card.pg-block { border-color: rgba(248, 113, 113, 0.3); }
      .pg-overlay-card.pg-analyzing { border-color: rgba(99, 102, 241, 0.3); }
      .pg-overlay-header {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 18px 20px 14px;
        border-bottom: 1px solid rgba(255,255,255,0.06);
      }
      .pg-overlay-icon { font-size: 28px; flex-shrink: 0; }
      .pg-overlay-title {
        font-size: 15px;
        font-weight: 700;
        letter-spacing: -0.3px;
      }
      .pg-overlay-subtitle {
        font-size: 12px;
        color: #6b7280;
        margin-top: 2px;
      }
      .pg-overlay-badge {
        display: inline-block;
        font-size: 10px;
        font-weight: 700;
        padding: 2px 8px;
        border-radius: 6px;
        margin-top: 4px;
        letter-spacing: 0.5px;
      }
      .pg-overlay-badge.pg-allow { background: rgba(52,211,153,0.15); color: #34d399; }
      .pg-overlay-badge.pg-redact { background: rgba(251,191,36,0.15); color: #fbbf24; }
      .pg-overlay-badge.pg-block { background: rgba(248,113,113,0.15); color: #f87171; }
      .pg-close-btn {
        position: absolute;
        top: 14px; right: 14px;
        background: none; border: none;
        color: #6b7280; font-size: 16px;
        cursor: pointer;
        padding: 4px 8px;
        border-radius: 6px;
        transition: all 0.15s;
      }
      .pg-close-btn:hover { background: rgba(255,255,255,0.06); color: #e8eaf0; }
      .pg-overlay-body { padding: 16px 20px; }
      .pg-reason {
        font-size: 13px;
        color: #9ba3b5;
        padding: 6px 0;
        line-height: 1.5;
      }
      .pg-comparison {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 12px;
        margin-top: 12px;
      }
      .pg-compare-label {
        font-size: 11px;
        font-weight: 600;
        color: #6b7280;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 6px;
      }
      .pg-compare-text {
        font-size: 12px;
        line-height: 1.6;
        padding: 10px 12px;
        border-radius: 8px;
        word-break: break-word;
      }
      .pg-compare-text.pg-original {
        background: rgba(248,113,113,0.08);
        border: 1px solid rgba(248,113,113,0.15);
        color: #fca5a5;
      }
      .pg-compare-text.pg-sanitized {
        background: rgba(52,211,153,0.08);
        border: 1px solid rgba(52,211,153,0.15);
        color: #6ee7b7;
      }
      .pg-overlay-footer {
        display: flex;
        gap: 10px;
        padding: 14px 20px 18px;
        border-top: 1px solid rgba(255,255,255,0.06);
      }
      .pg-btn {
        flex: 1;
        padding: 10px 16px;
        border: none;
        border-radius: 10px;
        font-size: 13px;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.15s;
        font-family: inherit;
      }
      .pg-btn-proceed {
        background: linear-gradient(135deg, #6366f1, #8b5cf6);
        color: white;
      }
      .pg-btn-proceed:hover {
        box-shadow: 0 4px 20px rgba(99,102,241,0.3);
        transform: translateY(-1px);
      }
      .pg-btn-cancel {
        background: rgba(255,255,255,0.06);
        color: #9ba3b5;
      }
      .pg-btn-cancel:hover {
        background: rgba(255,255,255,0.1);
        color: #e8eaf0;
      }
      .pg-spinner {
        width: 32px; height: 32px;
        border: 3px solid rgba(99,102,241,0.2);
        border-top-color: #6366f1;
        border-radius: 50%;
        animation: pgSpin 0.8s linear infinite;
        margin: 0 auto;
      }
      .pg-media-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: rgba(99, 102, 241, 0.12);
        border: 1px solid rgba(99, 102, 241, 0.25);
        color: #a5b4fc;
        font-size: 11.5px;
        font-weight: 600;
        padding: 4px 10px;
        border-radius: 6px;
        margin-bottom: 10px;
      }
      .pg-media-list {
        display: flex;
        flex-wrap: wrap;
        gap: 6px;
        margin-top: 6px;
        margin-bottom: 10px;
      }
      .pg-media-chip {
        display: inline-flex;
        align-items: center;
        gap: 5px;
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 6px;
        padding: 3px 8px;
        font-size: 11px;
        color: #cbd5e1;
      }
      .pg-source-tag {
        display: inline-block;
        font-size: 10px;
        font-weight: 700;
        padding: 1px 6px;
        border-radius: 4px;
        background: rgba(99, 102, 241, 0.15);
        color: #a5b4fc;
        border: 1px solid rgba(99, 102, 241, 0.3);
        margin-right: 5px;
        vertical-align: middle;
      }
      .pg-source-tag.pg-source-media {
        background: rgba(236, 72, 153, 0.15);
        color: #f472b6;
        border-color: rgba(236, 72, 153, 0.3);
      }
      @keyframes pgSpin { to { transform: rotate(360deg); } }
      @keyframes pgFadeIn { from { opacity: 0; } to { opacity: 1; } }
      @keyframes pgFadeOut { from { opacity: 1; } to { opacity: 0; } }
    `;
    document.head.appendChild(style);
  }

  /* =========================================
     INITIALIZATION
     ========================================= */

  function init() {
    const site = detectSite();
    if (site === 'unknown') return;

    console.log(`[PromptGuard] Content script loaded on ${site}`);

    // Inject styles (needed for MAIN world where CSS manifest entry may not apply)
    injectStyles();

    // Wait for the editor to appear and attach listeners
    waitForEditorAndAttach();
  }

  // Wait for page to be ready
  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    init();
  } else {
    document.addEventListener('DOMContentLoaded', init);
  }
})();
