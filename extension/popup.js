/**
 * PromptGuard Chrome Extension — Popup Controller
 *
 * Manages the extension popup UI: toggle interception on/off,
 * check gateway health, detect current site.
 */

(function () {
  'use strict';

  const GATEWAY_URL = 'http://localhost:8000';
  const STORAGE_KEY = 'promptguard_enabled';

  const enableToggle = document.getElementById('enable-toggle');
  const gatewayDot = document.getElementById('gateway-dot');
  const gatewayStatus = document.getElementById('gateway-status');
  const currentSite = document.getElementById('current-site');

  // Load saved state
  chrome.storage.local.get([STORAGE_KEY], (result) => {
    const enabled = result[STORAGE_KEY] !== false;
    enableToggle.checked = enabled;
  });

  // Toggle handler
  enableToggle.addEventListener('change', () => {
    const enabled = enableToggle.checked;
    chrome.storage.local.set({ [STORAGE_KEY]: enabled });

    // Notify content scripts
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        chrome.tabs.sendMessage(tabs[0].id, {
          type: 'TOGGLE_PROMPTGUARD',
          enabled: enabled,
        }).catch(() => {});
      }
    });
  });

  // Check gateway health
  async function checkGateway() {
    try {
      const resp = await fetch(`${GATEWAY_URL}/health`, {
        signal: AbortSignal.timeout(3000),
      });
      if (resp.ok) {
        gatewayDot.className = 'status-dot online';
        gatewayStatus.textContent = 'Online';
        gatewayStatus.style.color = '#34d399';
      } else {
        throw new Error('Not OK');
      }
    } catch {
      gatewayDot.className = 'status-dot offline';
      gatewayStatus.textContent = 'Offline';
      gatewayStatus.style.color = '#f87171';
    }
  }

  // Detect current site
  function detectCurrentSite() {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (!tabs[0]) {
        currentSite.textContent = '—';
        return;
      }
      const url = tabs[0].url || '';
      if (url.includes('chatgpt.com') || url.includes('chat.openai.com')) {
        currentSite.textContent = '🤖 ChatGPT';
        currentSite.style.color = '#34d399';
      } else if (url.includes('claude.ai')) {
        currentSite.textContent = '🟠 Claude';
        currentSite.style.color = '#fbbf24';
      } else {
        currentSite.textContent = 'Not an LLM site';
        currentSite.style.color = '#6b7280';
      }
    });
  }

  // Init
  checkGateway();
  detectCurrentSite();
})();
