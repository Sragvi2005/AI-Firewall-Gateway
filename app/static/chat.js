/**
 * PromptGuard Chat — Client-side Controller
 *
 * Manages the chat interface, sends prompts through the PromptGuard gateway
 * for 4-stage pipeline inspection, and renders LLM responses with inline
 * security analysis badges and expandable detail panels.
 */

class PromptGuardChat {
  constructor() {
    this.messages = [];
    this.isLoading = false;
    this.messageCounter = 0;

    // DOM references
    this.chatMessages = document.getElementById('chat-messages');
    this.welcomeScreen = document.getElementById('welcome-screen');
    this.promptInput = document.getElementById('prompt-input');
    this.sendBtn = document.getElementById('send-btn');
    this.modelSelect = document.getElementById('model-select');
    this.mockToggle = document.getElementById('mock-toggle');
    this.apiKeyInput = document.getElementById('api-key-input');
    this.apiKeyField = document.getElementById('api-key-field');
    this.gatewayDot = document.getElementById('gateway-dot');
    this.gatewayStatusText = document.getElementById('gateway-status-text');
    this.toastContainer = document.getElementById('toast-container');

    this.init();
  }

  init() {
    // Bind events
    this.sendBtn.addEventListener('click', () => this.handleSend());
    this.promptInput.addEventListener('input', () => this.handleInputChange());
    this.promptInput.addEventListener('keydown', (e) => this.handleKeyDown(e));

    // Mock toggle → show/hide API key field
    this.mockToggle.addEventListener('change', () => {
      this.apiKeyField.style.display = this.mockToggle.checked ? 'none' : 'block';
    });

    // Welcome card clicks
    document.querySelectorAll('.welcome-card').forEach(card => {
      card.addEventListener('click', () => {
        const prompt = card.getAttribute('data-prompt');
        if (prompt) {
          this.promptInput.value = prompt;
          this.handleInputChange();
          this.promptInput.focus();
        }
      });
    });

    // Auto-resize textarea
    this.promptInput.addEventListener('input', () => this.autoResize());

    // Check gateway health
    this.checkGatewayHealth();
    setInterval(() => this.checkGatewayHealth(), 15000);
  }

  /* ==========================
     GATEWAY HEALTH
     ========================== */

  async checkGatewayHealth() {
    try {
      const resp = await fetch('/health', { signal: AbortSignal.timeout(3000) });
      if (resp.ok) {
        this.gatewayDot.classList.remove('offline');
        this.gatewayStatusText.textContent = 'Gateway Online';
      } else {
        throw new Error('Not OK');
      }
    } catch {
      this.gatewayDot.classList.add('offline');
      this.gatewayStatusText.textContent = 'Gateway Offline';
    }
  }

  /* ==========================
     INPUT HANDLING
     ========================== */

  handleInputChange() {
    const hasText = this.promptInput.value.trim().length > 0;
    this.sendBtn.disabled = !hasText || this.isLoading;
  }

  handleKeyDown(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      if (!this.sendBtn.disabled) {
        this.handleSend();
      }
    }
  }

  autoResize() {
    this.promptInput.style.height = 'auto';
    this.promptInput.style.height = Math.min(this.promptInput.scrollHeight, 180) + 'px';
  }

  /* ==========================
     SEND MESSAGE
     ========================== */

  async handleSend() {
    const text = this.promptInput.value.trim();
    if (!text || this.isLoading) return;

    // Hide welcome screen
    if (this.welcomeScreen) {
      this.welcomeScreen.style.display = 'none';
    }

    this.isLoading = true;
    this.sendBtn.disabled = true;
    this.promptInput.value = '';
    this.promptInput.style.height = 'auto';

    // Add user message
    const userMsgId = this.addMessage('user', text);

    // Show typing indicator
    const typingId = this.addTypingIndicator();

    // Build messages payload (include conversation history)
    const messagesPayload = this.messages
      .filter(m => m.role === 'user' || m.role === 'assistant')
      .map(m => ({ role: m.role, content: m.content }));

    try {
      const response = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: this.modelSelect.value,
          messages: messagesPayload,
          user: 'chat-ui-user'
        })
      });

      const data = await response.json();

      // Remove typing indicator
      this.removeTypingIndicator(typingId);

      // Update user message with security badge
      this.updateSecurityBadge(userMsgId, data.security);

      if (data.blocked) {
        // Show blocked message
        this.addBlockedMessage(data.security);
        this.showToast('🔴 Prompt blocked by PromptGuard security policy', 'error');
      } else {
        // Add assistant response
        const assistantContent = data.message?.content || 'No response received.';
        this.addMessage('assistant', assistantContent);

        if (data.security?.action === 'REDACT') {
          this.showToast('🟡 Sensitive data was redacted before forwarding to LLM', 'warning');
        }
      }

    } catch (err) {
      this.removeTypingIndicator(typingId);
      this.addMessage('assistant', '⚠️ Failed to connect to PromptGuard gateway. Please ensure the server is running on port 8000.');
      this.showToast('Connection error — is the gateway running?', 'error');
      console.error('Chat error:', err);
    }

    this.isLoading = false;
    this.handleInputChange();
    this.promptInput.focus();
  }

  /* ==========================
     MESSAGE RENDERING
     ========================== */

  addMessage(role, content) {
    const msgId = `msg-${++this.messageCounter}`;
    const now = new Date();
    const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    this.messages.push({ role, content, id: msgId, time: timeStr });

    const wrapper = document.createElement('div');
    wrapper.className = 'message-wrapper';
    wrapper.id = msgId;

    const avatarIcon = role === 'user' ? '👤' : '🛡️';
    const roleName = role === 'user' ? 'You' : 'PromptGuard AI';

    wrapper.innerHTML = `
      <div class="message ${role}">
        <div class="message-avatar">${avatarIcon}</div>
        <div class="message-body">
          <div class="message-role">
            ${roleName}
            <span class="message-timestamp">${timeStr}</span>
          </div>
          <div class="message-content">${this.escapeHtml(content)}</div>
          ${role === 'user' ? `<div class="security-badge-container" id="badge-${msgId}"></div>` : ''}
        </div>
      </div>
    `;

    this.chatMessages.appendChild(wrapper);
    this.scrollToBottom();
    return msgId;
  }

  addBlockedMessage(security) {
    const wrapper = document.createElement('div');
    wrapper.className = 'message-wrapper';

    const reasons = (security.reasons || []).map(r => `<div class="blocked-reason">• ${this.escapeHtml(r)}</div>`).join('');

    wrapper.innerHTML = `
      <div class="message assistant">
        <div class="message-avatar">⛔</div>
        <div class="message-body">
          <div class="message-role" style="color: var(--block-text)">Security Policy Violation</div>
          <div class="blocked-message">
            <div class="blocked-title">🚫 Request Blocked by PromptGuard Firewall</div>
            <div class="blocked-reason">This prompt was identified as a security threat and was <strong>not forwarded</strong> to the upstream LLM.</div>
            ${reasons}
          </div>
        </div>
      </div>
    `;

    this.chatMessages.appendChild(wrapper);
    this.scrollToBottom();

    // Push a placeholder into history so conversation context knows it was blocked
    this.messages.push({
      role: 'assistant',
      content: '[BLOCKED BY PROMPTGUARD]',
      id: `msg-${++this.messageCounter}`,
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    });
  }

  addTypingIndicator() {
    const id = `typing-${Date.now()}`;
    const wrapper = document.createElement('div');
    wrapper.className = 'message-wrapper';
    wrapper.id = id;

    wrapper.innerHTML = `
      <div class="message assistant">
        <div class="message-avatar">🛡️</div>
        <div class="message-body">
          <div class="message-role" style="color: var(--text-muted)">PromptGuard AI</div>
          <div class="typing-indicator">
            <div class="typing-dot"></div>
            <div class="typing-dot"></div>
            <div class="typing-dot"></div>
          </div>
        </div>
      </div>
    `;

    this.chatMessages.appendChild(wrapper);
    this.scrollToBottom();
    return id;
  }

  removeTypingIndicator(id) {
    const el = document.getElementById(id);
    if (el) el.remove();
  }

  /* ==========================
     SECURITY BADGE & DETAILS
     ========================== */

  updateSecurityBadge(msgId, security) {
    const container = document.getElementById(`badge-${msgId}`);
    if (!container || !security) return;

    const action = security.action; // ALLOW, REDACT, BLOCK
    const cssClass = action.toLowerCase();
    const icons = { ALLOW: '✅', REDACT: '🟡', BLOCK: '🔴' };
    const labels = { ALLOW: 'CLEAN — Passed All Stages', REDACT: 'REDACTED — Sensitive Data Masked', BLOCK: 'BLOCKED — Security Threat Detected' };

    const badgeId = `detail-${msgId}`;

    container.innerHTML = `
      <div class="security-badge ${cssClass}" id="toggle-${badgeId}" title="Click to view security analysis">
        <span class="badge-icon">${icons[action]}</span>
        <span>${labels[action]}</span>
        <span class="badge-arrow">▶</span>
      </div>
    `;

    // Click to expand/collapse details
    const badge = document.getElementById(`toggle-${badgeId}`);
    badge.addEventListener('click', () => {
      const existing = document.getElementById(badgeId);
      if (existing) {
        existing.classList.add('collapsing');
        setTimeout(() => existing.remove(), 200);
        badge.classList.remove('expanded');
      } else {
        badge.classList.add('expanded');
        const panel = this.buildSecurityPanel(security, badgeId);
        container.appendChild(panel);
      }
    });
  }

  buildSecurityPanel(security, panelId) {
    const panel = document.createElement('div');
    panel.className = 'security-details';
    panel.id = panelId;

    const pipeline = security.pipeline || {};
    const stages = pipeline.stages || [];

    // Stage cards
    const stageNames = ['PII', 'Secrets', 'Financial', 'Intent AI'];
    const stageIcons = ['🪪', '🔑', '💳', '🧠'];
    let stageCardsHtml = stages.map((s, i) => `
      <div class="stage-card ${s.passed ? 'passed' : 'failed'}">
        <div class="stage-icon">${stageIcons[i] || '🔍'}</div>
        <div class="stage-label">${stageNames[i] || s.stage_name}</div>
        <div class="stage-count">${s.passed ? '✓ Clean' : `${s.detection_count} found`}</div>
        <div class="stage-time">${s.execution_time_ms?.toFixed(1) || '—'}ms</div>
      </div>
    `).join('');

    // Prompt comparison (only for REDACT)
    let comparisonHtml = '';
    if (security.action === 'REDACT') {
      comparisonHtml = `
        <div class="detail-section">
          <div class="detail-title">Prompt Comparison</div>
          <div class="prompt-comparison">
            <div>
              <div class="prompt-box-label">Original</div>
              <div class="prompt-box original">${this.escapeHtml(security.original_prompt)}</div>
            </div>
            <div>
              <div class="prompt-box-label">Sanitized (sent to LLM)</div>
              <div class="prompt-box sanitized">${this.escapeHtml(security.redacted_prompt)}</div>
            </div>
          </div>
        </div>
      `;
    }

    // Entity list
    const allMatches = stages.flatMap(s => s.matches || []);
    let entitiesHtml = '';
    if (allMatches.length > 0) {
      const entityRows = allMatches.map(m => `
        <div class="entity-item">
          <span class="entity-type">${this.escapeHtml(m.entity_type)}</span>
          <span class="entity-snippet" title="${this.escapeHtml(m.text_snippet)}">${this.escapeHtml(m.text_snippet)}</span>
          <span class="entity-severity ${m.severity}">${m.severity}</span>
        </div>
      `).join('');

      entitiesHtml = `
        <div class="detail-section">
          <div class="detail-title">Detected Entities</div>
          <div class="entity-list">${entityRows}</div>
        </div>
      `;
    }

    panel.innerHTML = `
      <div class="detail-section">
        <div class="detail-title">Pipeline Stage Results</div>
        <div class="pipeline-stages">${stageCardsHtml}</div>
      </div>
      ${comparisonHtml}
      ${entitiesHtml}
    `;

    return panel;
  }

  /* ==========================
     UTILITIES
     ========================== */

  escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  scrollToBottom() {
    requestAnimationFrame(() => {
      this.chatMessages.scrollTop = this.chatMessages.scrollHeight;
    });
  }

  showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;

    this.toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.animation = 'toast-exit 0.3s var(--ease-in-out) forwards';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }
}

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  window.chat = new PromptGuardChat();
});
