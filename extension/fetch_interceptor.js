/**
 * PromptGuard — Fetch Interceptor (MAIN World)
 *
 * This script runs in the page's MAIN JavaScript world so it can override
 * window.fetch.  It catches the actual HTTP requests that each LLM site
 * makes to its backend, extracts the user prompt from the request body,
 * sends it to the PromptGuard gateway for inspection, and then:
 *
 *   ALLOW  → forwards the original request unchanged
 *   REDACT → rewrites the request body with the sanitised prompt
 *   BLOCK  → aborts the request and shows a notification
 *
 * This is the *only* reliable interception layer.  DOM-level event
 * interception (click / keydown) cannot prevent modern React / SPA
 * frameworks from reading their own internal state and making API calls.
 *
 * Communication with the ISOLATED-world content script (content.js) happens
 * via CustomEvents on `window`.
 */
(function () {
  'use strict';

  const GATEWAY_URL  = 'http://localhost:8000';
  const INSPECT_EP   = `${GATEWAY_URL}/api/inspect`;

  // ── Per-site API-endpoint patterns ──────────────────────────────────
  // Each entry: { urlPattern, extractPrompt(body), replacePrompt(body, redacted) }

  const LLM_ENDPOINTS = [
    // ── ChatGPT ──
    {
      name: 'chatgpt',
      match: (url) => /chatgpt\.com\/backend-api\/conversation/.test(url)
                    || /chat\.openai\.com\/backend-api\/conversation/.test(url),
      extractPrompt(body) {
        try {
          const obj = typeof body === 'string' ? JSON.parse(body) : body;
          const msgs = obj.messages || [];
          const parts = [];
          for (const m of msgs) {
            const content = m?.content;
            if (!content) continue;
            if (Array.isArray(content.parts)) {
              parts.push(...content.parts.filter(p => typeof p === 'string' && !/^data:(?:image\/|application\/pdf;)/i.test(p)));
              parts.push(...content.parts
                .filter(p => p && typeof p === 'object' && typeof p.text === 'string')
                .map(p => p.text));
            }
          }
          return parts.join('\n');
        } catch { return ''; }
      },
      replacePrompt(body, redacted) {
        try {
          const obj = typeof body === 'string' ? JSON.parse(body) : body;
          const messages = obj.messages || [];
          for (let i = messages.length - 1; i >= 0; i--) {
            const content = messages[i]?.content;
            if (!content || !Array.isArray(content.parts)) continue;
            const mediaParts = content.parts.filter(p =>
              (typeof p === 'string' && /^data:(?:image\/|application\/pdf;)/i.test(p))
              || (p && typeof p === 'object' && (p.content_type === 'image_asset_pointer' || p.type === 'image_url'))
            );
            const textParts = content.parts.filter(p =>
              (typeof p === 'string' && !/^data:(?:image\/|application\/pdf;)/i.test(p))
              || (p && typeof p === 'object' && typeof p.text === 'string')
            );
            if (textParts.length) {
              const first = textParts[0];
              const replacement = typeof first === 'string' ? redacted : { ...first, text: redacted };
              content.parts = [replacement, ...mediaParts];
              break;
            }
          }
          return JSON.stringify(obj);
        } catch { return body; }
      },
    },

    // ── Claude ──
    {
      name: 'claude',
      match: (url) => /claude\.ai\/api\//.test(url)
                    && (/completion/.test(url) || /append_message/.test(url) || /chat_conversations/.test(url) || /retry/.test(url)),
      extractPrompt(body) {
        try {
          const obj = typeof body === 'string' ? JSON.parse(body) : body;
          // Claude API uses "prompt" or nested content
          if (typeof obj.prompt === 'string') return obj.prompt;
          if (typeof obj.content === 'string') return obj.content;
          // Sometimes messages array
          if (Array.isArray(obj.messages)) {
            return obj.messages.filter(m => m.role === 'user').map(m => m.content || '').join('\n');
          }
          // Fallback: stringify and scan
          return '';
        } catch { return ''; }
      },
      replacePrompt(body, redacted) {
        try {
          const obj = typeof body === 'string' ? JSON.parse(body) : body;
          if (typeof obj.prompt === 'string') { obj.prompt = redacted; }
          if (typeof obj.content === 'string') { obj.content = redacted; }
          if (Array.isArray(obj.messages)) {
            for (const m of obj.messages) {
              if (m.role === 'user' && typeof m.content === 'string') m.content = redacted;
            }
          }
          return JSON.stringify(obj);
        } catch { return body; }
      },
    },

    // ── Gemini ──
    {
      name: 'gemini',
      match: (url) => /gemini\.google\.com\/_\//.test(url)
                    || (/generativelanguage\.googleapis\.com/.test(url) && /generate/i.test(url)),
      // Gemini uses a complex protobuf/multipart format; we intercept
      // the text portion if it's embedded as JSON.
      extractPrompt(body) {
        if (typeof body !== 'string') return '';
        try {
          // Often the body is a nested array encoded as JSON-like text
          const match = body.match(/"([^"]{10,})"/g);
          if (match) {
            // return the longest string (likely the user prompt)
            return match.reduce((a, b) => a.length > b.length ? a : b, '').replace(/^"|"$/g, '');
          }
        } catch {}
        return '';
      },
      replacePrompt(body, redacted) {
        if (typeof body !== 'string') return body;
        try {
          // Find the longest quoted string and replace it
          const match = body.match(/"([^"]{10,})"/g);
          if (match) {
            const longest = match.reduce((a, b) => a.length > b.length ? a : b, '');
            return body.replace(longest, `"${redacted.replace(/"/g, '\\"')}"`);
          }
        } catch {}
        return body;
      },
    },

    // ── Mistral ──
    {
      name: 'mistral',
      match: (url) => /chat\.mistral\.ai\/api\/chat/.test(url)
                    || (/api\.mistral\.ai/.test(url) && /chat\/completions/.test(url)),
      extractPrompt(body) {
        try {
          const obj = typeof body === 'string' ? JSON.parse(body) : body;
          const msgs = obj.messages || [];
          return msgs.filter(m => m.role === 'user').map(m => m.content || '').join('\n');
        } catch { return ''; }
      },
      replacePrompt(body, redacted) {
        try {
          const obj = typeof body === 'string' ? JSON.parse(body) : body;
          for (const m of (obj.messages || [])) {
            if (m.role === 'user') m.content = redacted;
          }
          return JSON.stringify(obj);
        } catch { return body; }
      },
    },

    // ── Groq ──
    {
      name: 'groq',
      match: (url) => (/groq\.com/.test(url) && (/chat/.test(url) || /completions/.test(url))),
      extractPrompt(body) {
        try {
          const obj = typeof body === 'string' ? JSON.parse(body) : body;
          const msgs = obj.messages || [];
          return msgs.filter(m => m.role === 'user').map(m => m.content || '').join('\n');
        } catch { return ''; }
      },
      replacePrompt(body, redacted) {
        try {
          const obj = typeof body === 'string' ? JSON.parse(body) : body;
          for (const m of (obj.messages || [])) {
            if (m.role === 'user') m.content = redacted;
          }
          return JSON.stringify(obj);
        } catch { return body; }
      },
    },

    // ── Cohere ──
    {
      name: 'cohere',
      match: (url) => /cohere\.com/.test(url) && (/chat/.test(url) || /generate/.test(url)),
      extractPrompt(body) {
        try {
          const obj = typeof body === 'string' ? JSON.parse(body) : body;
          if (typeof obj.message === 'string') return obj.message;
          if (typeof obj.prompt === 'string') return obj.prompt;
          const msgs = obj.messages || obj.chat_history || [];
          return msgs.filter(m => m.role === 'user' || m.role === 'USER')
                     .map(m => m.content || m.message || '').join('\n');
        } catch { return ''; }
      },
      replacePrompt(body, redacted) {
        try {
          const obj = typeof body === 'string' ? JSON.parse(body) : body;
          if (typeof obj.message === 'string') obj.message = redacted;
          if (typeof obj.prompt === 'string') obj.prompt = redacted;
          for (const m of (obj.messages || obj.chat_history || [])) {
            if ((m.role === 'user' || m.role === 'USER') && typeof (m.content || m.message) === 'string') {
              if ('content' in m) m.content = redacted;
              if ('message' in m) m.message = redacted;
            }
          }
          return JSON.stringify(obj);
        } catch { return body; }
      },
    },
  ];

  // ── State ──
  let isEnabled = true;
  // Listen for toggle messages from the content script
  window.addEventListener('promptguard-toggle', (e) => {
    if (e.detail && typeof e.detail.enabled === 'boolean') {
      isEnabled = e.detail.enabled;
    }
  });

  // ── Save the real fetch ──
  const _originalFetch = window.fetch;

  // ── Helper: call the gateway for inspection ──
  async function inspectWithGateway(promptText, attachments = []) {
    try {
      const resp = await _originalFetch(INSPECT_EP, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          prompt: promptText,
          user: 'chrome-extension-user',
          ...(attachments.length ? { attachments: attachments.map(({ filename, content_base64, mime_type }) => ({ filename, content_base64, mime_type })) } : {}),
        }),
      });
      if (!resp.ok) return null;
      return await resp.json();
    } catch (err) {
      console.warn('[PromptGuard:Fetch] Gateway unreachable:', err.message);
      return null;
    }
  }

  // Walk media data URIs embedded in request JSON so they can be scanned and
  // replaced using the gateway's attachment inspection response.
  function collectInlineMedia(bodyStr) {
    let parsed;
    try { parsed = JSON.parse(bodyStr); } catch { return []; }
    const found = [];
    const walk = (value, path = []) => {
      if (typeof value === 'string') {
        const match = value.match(/^data:(image\/[a-z0-9.+-]+|application\/pdf);base64,/i);
        if (match) {
          const mimeType = match[1].toLowerCase();
          const extension = mimeType === 'application/pdf' ? 'pdf' : (mimeType.split('/')[1] || 'img');
          found.push({
            path,
            filename: `promptguard-inline-${found.length + 1}.${extension}`,
            content_base64: value,
            mime_type: mimeType,
          });
        }
      } else if (Array.isArray(value)) {
        value.forEach((item, index) => walk(item, [...path, index]));
      } else if (value && typeof value === 'object') {
        for (const [key, item] of Object.entries(value)) walk(item, [...path, key]);
      }
    };
    walk(parsed);
    return found;
  }

  function replaceInlineMedia(bodyStr, media, sanitizedByName) {
    if (!media.length) return bodyStr;
    let parsed;
    try { parsed = JSON.parse(bodyStr); } catch { return bodyStr; }
    const replacements = new Map(media.flatMap(item => {
      const sanitized = sanitizedByName.get(item.filename);
      return sanitized?.content_base64 ? [[item.content_base64, sanitized.content_base64]] : [];
    }));
    const walk = value => {
      if (typeof value === 'string') return replacements.get(value) || value;
      if (Array.isArray(value)) return value.map(walk);
      if (value && typeof value === 'object') {
        for (const [key, item] of Object.entries(value)) value[key] = walk(item);
      }
      return value;
    };
    parsed = walk(parsed);
    return JSON.stringify(parsed);
  }

  function rejectRequest(reasons = []) {
    showBlockNotification(reasons.length ? reasons : ['PromptGuard could not safely sanitize media in this request']);
    return new Response(JSON.stringify({
      error: { message: 'PromptGuard: request blocked because media could not be safely inspected or sanitized', type: 'promptguard_block' }
    }), { status: 403, headers: { 'Content-Type': 'application/json' } });
  }

  // ── Show a minimal block notification (injected directly since we're in MAIN world) ──
  function showBlockNotification(reasons) {
    // Dispatch event so content.js can show its rich overlay if it's listening
    window.dispatchEvent(new CustomEvent('promptguard-fetch-blocked', {
      detail: { reasons }
    }));
  }

  function showRedactNotification(original, redacted, reasons) {
    window.dispatchEvent(new CustomEvent('promptguard-fetch-redacted', {
      detail: { original, redacted, reasons }
    }));
  }

  // ── Patched fetch ──
  window.fetch = async function (resource, init) {
    // Only intercept when enabled
    if (!isEnabled) return _originalFetch.apply(this, arguments);

    // Determine URL
    const url = typeof resource === 'string'
      ? resource
      : (resource instanceof Request ? resource.url : String(resource));
    const method = (init?.method || (resource instanceof Request ? resource.method : 'GET')).toUpperCase();

    // Only intercept POST requests
    if (method !== 'POST') return _originalFetch.apply(this, arguments);

    // Check if this URL matches any LLM endpoint
    const endpoint = LLM_ENDPOINTS.find(ep => ep.match(url));
    if (!endpoint) return _originalFetch.apply(this, arguments);

    // Extract the request body
    let bodyStr = '';
    if (init?.body) {
      if (typeof init.body === 'string') {
        bodyStr = init.body;
      } else if (init.body instanceof Blob) {
        bodyStr = await init.body.text();
      } else if (init.body instanceof ArrayBuffer || init.body instanceof Uint8Array) {
        bodyStr = new TextDecoder().decode(init.body);
      } else if (init.body instanceof FormData) {
        // Can't easily rewrite FormData; pass through
        return _originalFetch.apply(this, arguments);
      } else if (init.body instanceof ReadableStream) {
        // Read the stream, then reconstruct
        const reader = init.body.getReader();
        const chunks = [];
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          chunks.push(value);
        }
        const combined = new Uint8Array(chunks.reduce((a, c) => a + c.length, 0));
        let offset = 0;
        for (const chunk of chunks) { combined.set(chunk, offset); offset += chunk.length; }
        bodyStr = new TextDecoder().decode(combined);
      } else {
        bodyStr = String(init.body);
      }
    } else if (resource instanceof Request) {
      try { bodyStr = await resource.clone().text(); } catch {}
    }

    if (!bodyStr) return _originalFetch.apply(this, arguments);

    // Extract the user prompt
    const promptText = endpoint.extractPrompt(bodyStr);
    const inlineMedia = collectInlineMedia(bodyStr);
    if ((!promptText || !promptText.trim()) && inlineMedia.length === 0) return _originalFetch.apply(this, arguments);

    console.log(`[PromptGuard:Fetch] Intercepted ${endpoint.name} API call, prompt length: ${promptText.length}`);

    // ── Inspect via gateway ──
    const result = await inspectWithGateway(promptText || '', inlineMedia);

    if (!result) {
      return rejectRequest(['PromptGuard could not reach the gateway; the request was held back']);
    }

    const action = result.action;
    if (inlineMedia.length) {
      const extractions = result.pipeline?.media_scan?.extractions || [];
      const scannedNames = new Set(extractions.map(item => item.filename));
      if (inlineMedia.some(item => !scannedNames.has(item.filename))) {
        return rejectRequest(['PromptGuard did not scan every embedded media item; the request was held back']);
      }
      const extractionFailures = extractions
        .filter(item => !item.success)
        .map(item => item.filename);
      if (inlineMedia.some(item => extractionFailures.includes(item.filename))) {
        return rejectRequest(['PromptGuard could not inspect embedded media; the request was held back']);
      }
    }

    if (action === 'ALLOW') {
      console.log(`[PromptGuard:Fetch] ALLOW — ${endpoint.name} request passed`);
      return _originalFetch.apply(this, arguments);
    }

    if (action === 'REDACT') {
      const redactedPrompt = result.redacted_prompt || promptText;
      const mediaMatches = (result.pipeline?.stage_results || result.pipeline?.stages || [])
        .flatMap(stage => stage.matches || [])
        .filter(match => (match.source || '').startsWith('media:'));
      const sensitiveNames = new Set(mediaMatches.map(match => match.source.slice('media:'.length)));
      const sanitizedByName = new Map((result.sanitized_attachments || []).map(item => [item.filename, item]));
      const failedNames = new Set(result.media_redaction_failures || []);
      const extractionFailures = (result.pipeline?.media_scan?.extractions || [])
        .filter(item => !item.success)
        .map(item => item.filename);
      if (inlineMedia.some(item => failedNames.has(item.filename) || extractionFailures.includes(item.filename))) {
        return rejectRequest(['PromptGuard could not inspect or safely redact embedded media; the request was held back']);
      }
      if ([...sensitiveNames].some(name => inlineMedia.some(item => item.filename === name) && !sanitizedByName.get(name)?.content_base64)) {
        return rejectRequest(['PromptGuard detected sensitive media but could not produce a sanitized copy; the request was held back']);
      }
      console.log(`[PromptGuard:Fetch] REDACT — rewriting ${endpoint.name} request body`);
      showRedactNotification(promptText, redactedPrompt, result.reasons || []);
      let newBody = endpoint.replacePrompt(bodyStr, redactedPrompt);
      newBody = replaceInlineMedia(newBody, inlineMedia, sanitizedByName);
      const newInit = { ...(init || {}), body: newBody };
      return _originalFetch.call(this, resource, newInit);
    }

    if (action === 'BLOCK') {
      console.log(`[PromptGuard:Fetch] BLOCK — aborting ${endpoint.name} request`);
      showBlockNotification(result.reasons || []);
      // Return a fake error response so the LLM UI handles it gracefully
      return new Response(JSON.stringify({
        error: { message: 'PromptGuard: request blocked due to security policy', type: 'promptguard_block' }
      }), { status: 403, headers: { 'Content-Type': 'application/json' } });
    }

    return rejectRequest(['PromptGuard returned an unknown inspection result; the request was held back']);
  };

  // Also intercept XMLHttpRequest for LLMs that use it (rare but possible)
  const _origXhrOpen = XMLHttpRequest.prototype.open;
  const _origXhrSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function (method, url, ...rest) {
    this._pgMethod = method;
    this._pgUrl = url;
    return _origXhrOpen.call(this, method, url, ...rest);
  };

  XMLHttpRequest.prototype.send = function (body) {
    if (!isEnabled || this._pgMethod?.toUpperCase() !== 'POST') {
      return _origXhrSend.call(this, body);
    }

    const endpoint = LLM_ENDPOINTS.find(ep => ep.match(this._pgUrl || ''));
    if (!endpoint || !body || typeof body !== 'string') {
      return _origXhrSend.call(this, body);
    }

    const promptText = endpoint.extractPrompt(body);
    const inlineMedia = collectInlineMedia(body);
    if ((!promptText || !promptText.trim()) && inlineMedia.length === 0) {
      return _origXhrSend.call(this, body);
    }

    console.log(`[PromptGuard:XHR] Intercepted ${endpoint.name} API call, prompt length: ${(promptText || '').length}`);

    // Use sync approach: we can't await in XHR send, so we use
    // a sync XMLHttpRequest to the gateway (blocking but necessary)
    let inspectionSucceeded = false;
    try {
      const syncXhr = new XMLHttpRequest();
      syncXhr.open('POST', INSPECT_EP, false); // synchronous
      syncXhr.setRequestHeader('Content-Type', 'application/json');
      syncXhr.send(JSON.stringify({
        prompt: promptText || '',
        user: 'chrome-extension-user',
        ...(inlineMedia.length ? { attachments: inlineMedia.map(({ filename, content_base64, mime_type }) => ({ filename, content_base64, mime_type })) } : {}),
      }));

      if (syncXhr.status === 200) {
        inspectionSucceeded = true;
        const result = JSON.parse(syncXhr.responseText);

        if (result.action === 'REDACT') {
          const mediaMatches = (result.pipeline?.stage_results || result.pipeline?.stages || [])
            .flatMap(stage => stage.matches || [])
            .filter(match => (match.source || '').startsWith('media:'));
          const sensitiveNames = new Set(mediaMatches.map(match => match.source.slice('media:'.length)));
          const sanitizedByName = new Map((result.sanitized_attachments || []).map(item => [item.filename, item]));
          const failedNames = new Set(result.media_redaction_failures || []);
          const extractions = result.pipeline?.media_scan?.extractions || [];
          const scannedNames = new Set(extractions.map(item => item.filename));
          const extractionFailures = extractions
            .filter(item => !item.success)
            .map(item => item.filename);
          if (
            inlineMedia.some(item => !scannedNames.has(item.filename))
            ||
            inlineMedia.some(item => failedNames.has(item.filename) || extractionFailures.includes(item.filename))
            || [...sensitiveNames].some(name => inlineMedia.some(item => item.filename === name) && !sanitizedByName.get(name)?.content_base64)
          ) {
            showBlockNotification(['PromptGuard could not safely inspect or sanitize embedded media; the request was held back']);
            this.abort();
            return;
          }
          let newBody = endpoint.replacePrompt(body, result.redacted_prompt || promptText || '');
          newBody = replaceInlineMedia(newBody, inlineMedia, sanitizedByName);
          console.log(`[PromptGuard:XHR] REDACT — rewriting ${endpoint.name} XHR body`);
          showRedactNotification(promptText || '', result.redacted_prompt || promptText || '', result.reasons || []);
          return _origXhrSend.call(this, newBody);
        }

        if (result.action === 'BLOCK') {
          console.log(`[PromptGuard:XHR] BLOCK — aborting ${endpoint.name} XHR`);
          showBlockNotification(result.reasons || []);
          this.abort();
          return;
        }

        if (inlineMedia.length && result.action === 'ALLOW') {
          const extractions = result.pipeline?.media_scan?.extractions || [];
          const scannedNames = new Set(extractions.map(item => item.filename));
          const extractionFailures = extractions
            .filter(item => !item.success)
            .map(item => item.filename);
          if (inlineMedia.some(item => !scannedNames.has(item.filename) || extractionFailures.includes(item.filename))) {
            showBlockNotification(['PromptGuard could not inspect embedded media; the request was held back']);
            this.abort();
            return;
          }
        }
        if (inlineMedia.length && !['ALLOW', 'REDACT', 'BLOCK'].includes(result.action)) {
          showBlockNotification(['PromptGuard returned an unknown inspection result for embedded media; the request was held back']);
          this.abort();
          return;
        }
        if (!['ALLOW', 'REDACT', 'BLOCK'].includes(result.action)) {
          showBlockNotification(['PromptGuard returned an unknown inspection result; the request was held back']);
          this.abort();
          return;
        }
      }
    } catch (err) {
      console.warn('[PromptGuard:XHR] Gateway inspection failed:', err);
    }

    if (!inspectionSucceeded) {
      showBlockNotification(['PromptGuard could not reach the gateway; the request was held back']);
      this.abort();
      return;
    }

    // ALLOW or error — send original
    return _origXhrSend.call(this, body);
  };

  console.log('[PromptGuard] Fetch interceptor loaded (MAIN world) — monitoring LLM API calls');
})();
