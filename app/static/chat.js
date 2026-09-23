/**
 * PromptGuard Chat — Client-side Controller
 *
 * Manages the chat interface, sends prompts through the PromptGuard gateway
 * for 4-stage pipeline inspection, and renders LLM responses with inline
 * security analysis badges and expandable detail panels.
 *
 * Supports multiple LLM providers: OpenAI, Anthropic Claude, Google Gemini,
 * Groq, Mistral AI, Cohere, and Custom OpenAI-compatible endpoints.
 *
 * Supports file attachments (images, PDFs, DOCX, XLSX, CSV, code, etc.)
 * for media-aware sensitive data detection.
 */

// Provider → model mapping
const PROVIDER_MODELS = {
  openai: [
    { value: 'gpt-4o', label: 'GPT-4o' },
    { value: 'gpt-4o-mini', label: 'GPT-4o Mini' },
    { value: 'gpt-4.1', label: 'GPT-4.1' },
    { value: 'gpt-4.1-mini', label: 'GPT-4.1 Mini' },
    { value: 'gpt-4.1-nano', label: 'GPT-4.1 Nano' },
    { value: 'o3-mini', label: 'o3-mini' },
    { value: 'gpt-3.5-turbo', label: 'GPT-3.5 Turbo' },
  ],
  anthropic: [
    { value: 'claude-sonnet-4-20250514', label: 'Claude Sonnet 4' },
    { value: 'claude-opus-4-20250514', label: 'Claude Opus 4' },
    { value: 'claude-3-5-haiku-20241022', label: 'Claude 3.5 Haiku' },
  ],
  gemini: [
    { value: 'gemini-2.5-pro-preview-05-06', label: 'Gemini 2.5 Pro' },
    { value: 'gemini-2.5-flash-preview-05-20', label: 'Gemini 2.5 Flash' },
    { value: 'gemini-2.0-flash', label: 'Gemini 2.0 Flash' },
    { value: 'gemini-2.0-flash-lite', label: 'Gemini 2.0 Flash Lite' },
  ],
  groq: [
    { value: 'llama-3.3-70b-versatile', label: 'Llama 3.3 70B' },
    { value: 'llama-3.1-8b-instant', label: 'Llama 3.1 8B' },
    { value: 'gemma2-9b-it', label: 'Gemma 2 9B' },
    { value: 'mixtral-8x7b-32768', label: 'Mixtral 8x7B' },
  ],
  mistral: [
    { value: 'mistral-large-latest', label: 'Mistral Large' },
    { value: 'mistral-medium-latest', label: 'Mistral Medium' },
    { value: 'mistral-small-latest', label: 'Mistral Small' },
    { value: 'open-mistral-nemo', label: 'Mistral Nemo' },
    { value: 'codestral-latest', label: 'Codestral' },
  ],
  cohere: [
    { value: 'command-r-plus', label: 'Command R+' },
    { value: 'command-r', label: 'Command R' },
    { value: 'command-a-03-2025', label: 'Command A' },
  ],
  custom: [
    { value: 'default', label: 'Default Model' },
  ],
};

// Provider → API key placeholder
const PROVIDER_KEY_INFO = {
  openai:    { label: 'OpenAI API Key',    placeholder: 'sk-...' },
  anthropic: { label: 'Anthropic API Key', placeholder: 'sk-ant-...' },
  gemini:    { label: 'Gemini API Key',    placeholder: 'AIza...' },
  groq:      { label: 'Groq API Key',      placeholder: 'gsk_...' },
  mistral:   { label: 'Mistral API Key',   placeholder: 'Enter key...' },
  cohere:    { label: 'Cohere API Key',    placeholder: 'Enter key...' },
  custom:    { label: 'API Key (optional)', placeholder: 'Bearer token...' },
};

// File type icons
const FILE_ICONS = {
  'image': '🖼️',
  'pdf': '📄',
  'docx': '📝',
  'xlsx': '📊',
  'csv': '📊',
  'code': '💻',
  'text': '📃',
  'default': '📎',
};

function getFileIcon(filename) {
  const ext = filename.split('.').pop()?.toLowerCase() || '';
  if (['png','jpg','jpeg','gif','bmp','tiff','webp'].includes(ext)) return FILE_ICONS.image;
  if (ext === 'pdf') return FILE_ICONS.pdf;
  if (ext === 'docx') return FILE_ICONS.docx;
  if (['xlsx','xls'].includes(ext)) return FILE_ICONS.xlsx;
  if (ext === 'csv') return FILE_ICONS.csv;
  if (['py','js','ts','java','go','rs','rb','sh','sql','html','css'].includes(ext)) return FILE_ICONS.code;
  if (['txt','log','env','ini','conf','cfg','md','json','xml','yaml','yml'].includes(ext)) return FILE_ICONS.text;
  return FILE_ICONS.default;
}

function formatFileSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

class PromptGuardChat {
  constructor() {
    this.messages = [];
    this.isLoading = false;
    this.messageCounter = 0;
    this.pendingAttachments = []; // {filename, content_base64, mime_type, size, previewUrl?}

    // DOM references
    this.chatMessages = document.getElementById('chat-messages');
    this.welcomeScreen = document.getElementById('welcome-screen');
    this.promptInput = document.getElementById('prompt-input');
    this.sendBtn = document.getElementById('send-btn');
    this.attachBtn = document.getElementById('attach-btn');
    this.fileInput = document.getElementById('file-input');
    this.attachmentPreviewArea = document.getElementById('attachment-preview-area');
    this.dragOverlay = document.getElementById('drag-overlay');
    this.providerSelect = document.getElementById('provider-select');
    this.modelSelect = document.getElementById('model-select');
    this.mockToggle = document.getElementById('mock-toggle');
    this.apiKeyInput = document.getElementById('api-key-input');
    this.apiKeyField = document.getElementById('api-key-field');
    this.apiKeyLabel = document.getElementById('api-key-label');
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

    // Provider selector → update models and API key label
    this.providerSelect.addEventListener('change', () => this.handleProviderChange());

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

    // ── File attachment handling ──────────────────────────────────────
    this.attachBtn.addEventListener('click', () => this.fileInput.click());
    this.fileInput.addEventListener('change', (e) => this.handleFileSelect(e));

    // Paste handler (for clipboard images)
    this.promptInput.addEventListener('paste', (e) => this.handlePaste(e));

    // Drag and drop
    const chatMain = document.querySelector('.chat-main');
    chatMain.addEventListener('dragenter', (e) => this.handleDragEnter(e));
    chatMain.addEventListener('dragover', (e) => this.handleDragOver(e));
    chatMain.addEventListener('dragleave', (e) => this.handleDragLeave(e));
    chatMain.addEventListener('drop', (e) => this.handleDrop(e));

    // Check gateway health
    this.checkGatewayHealth();
    setInterval(() => this.checkGatewayHealth(), 15000);

    // Initialize model dropdown for default provider
    this.handleProviderChange();
  }

  /* ==========================
     PROVIDER / MODEL HANDLING
     ========================== */

  handleProviderChange() {
    const provider = this.providerSelect.value;
    const models = PROVIDER_MODELS[provider] || PROVIDER_MODELS.openai;

    // Update model dropdown
    this.modelSelect.innerHTML = '';
    models.forEach(m => {
      const opt = document.createElement('option');
      opt.value = m.value;
      opt.textContent = m.label;
      this.modelSelect.appendChild(opt);
    });

    // Update API key field label and placeholder
    const keyInfo = PROVIDER_KEY_INFO[provider] || PROVIDER_KEY_INFO.openai;
    if (this.apiKeyLabel) {
      this.apiKeyLabel.textContent = keyInfo.label;
    }
    if (this.apiKeyInput) {
      this.apiKeyInput.placeholder = keyInfo.placeholder;
    }
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
    const hasAttachments = this.pendingAttachments.length > 0;
    this.sendBtn.disabled = (!hasText && !hasAttachments) || this.isLoading;
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
     FILE ATTACHMENT HANDLING
     ========================== */

  async handleFileSelect(e) {
    const files = Array.from(e.target.files || []);
    for (const file of files) {
      await this.addAttachment(file);
    }
    // Reset file input so same file can be re-attached
    this.fileInput.value = '';
  }

  async handlePaste(e) {
    const items = Array.from(e.clipboardData?.items || []);
    for (const item of items) {
      if (item.type.startsWith('image/')) {
        e.preventDefault();
        const file = item.getAsFile();
        if (file) {
          await this.addAttachment(file);
        }
      }
    }
  }

  handleDragEnter(e) {
    e.preventDefault();
    e.stopPropagation();
    this.dragOverlay.classList.add('visible');
  }

  handleDragOver(e) {
    e.preventDefault();
    e.stopPropagation();
  }

  handleDragLeave(e) {
    e.preventDefault();
    e.stopPropagation();
    // Only hide if leaving the main area
    if (!e.relatedTarget || !document.querySelector('.chat-main').contains(e.relatedTarget)) {
      this.dragOverlay.classList.remove('visible');
    }
  }

  async handleDrop(e) {
    e.preventDefault();
    e.stopPropagation();
    this.dragOverlay.classList.remove('visible');

    const files = Array.from(e.dataTransfer?.files || []);
    for (const file of files) {
      await this.addAttachment(file);
    }
  }

  async addAttachment(file) {
    const MAX_SIZE = 10 * 1024 * 1024; // 10 MB
    if (file.size > MAX_SIZE) {
      this.showToast(`File "${file.name}" exceeds 10 MB limit`, 'error');
      return;
    }

    // Check for duplicate
    if (this.pendingAttachments.some(a => a.filename === file.name && a.size === file.size)) {
      this.showToast(`"${file.name}" is already attached`, 'warning');
      return;
    }

    try {
      const base64 = await this.fileToBase64(file);
      const attachment = {
        filename: file.name,
        content_base64: base64,
        mime_type: file.type || 'application/octet-stream',
        size: file.size,
        previewUrl: null,
      };

      // Generate image thumbnail preview
      if (file.type.startsWith('image/')) {
        attachment.previewUrl = URL.createObjectURL(file);
      }

      this.pendingAttachments.push(attachment);
      this.renderAttachmentPreviews();
      this.handleInputChange();
      this.showToast(`📎 Attached: ${file.name}`, 'info');
    } catch (err) {
      console.error('Failed to read file:', err);
      this.showToast(`Failed to read file: ${file.name}`, 'error');
    }
  }

  fileToBase64(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result.split(',')[1]); // Strip data URI prefix
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });
  }

  removeAttachment(index) {
    const att = this.pendingAttachments[index];
    if (att?.previewUrl) {
      URL.revokeObjectURL(att.previewUrl);
    }
    this.pendingAttachments.splice(index, 1);
    this.renderAttachmentPreviews();
    this.handleInputChange();
  }

  renderAttachmentPreviews() {
    if (!this.attachmentPreviewArea) return;

    if (this.pendingAttachments.length === 0) {
      this.attachmentPreviewArea.innerHTML = '';
      this.attachmentPreviewArea.classList.remove('visible');
      return;
    }

    this.attachmentPreviewArea.classList.add('visible');
    this.attachmentPreviewArea.innerHTML = this.pendingAttachments.map((att, i) => {
      const icon = getFileIcon(att.filename);
      const sizeStr = formatFileSize(att.size);
      const previewImg = att.previewUrl
        ? `<img class="attachment-thumb" src="${att.previewUrl}" alt="${this.escapeHtml(att.filename)}">`
        : `<span class="attachment-icon-large">${icon}</span>`;

      return `
        <div class="attachment-preview-item" title="${this.escapeHtml(att.filename)} (${sizeStr})">
          ${previewImg}
          <div class="attachment-info">
            <span class="attachment-name">${this.escapeHtml(att.filename)}</span>
            <span class="attachment-size">${sizeStr}</span>
          </div>
          <button class="attachment-remove" onclick="window.chat.removeAttachment(${i})" title="Remove">×</button>
        </div>
      `;
    }).join('');
  }

  /* ==========================
     SEND MESSAGE
     ========================== */

  async handleSend() {
    const text = this.promptInput.value.trim();
    const attachments = [...this.pendingAttachments];

    if ((!text && attachments.length === 0) || this.isLoading) return;

    // Hide welcome screen
    if (this.welcomeScreen) {
      this.welcomeScreen.style.display = 'none';
    }

    this.isLoading = true;
    this.sendBtn.disabled = true;
    this.promptInput.value = '';
    this.promptInput.style.height = 'auto';

    // Clear pending attachments
    this.pendingAttachments = [];
    this.renderAttachmentPreviews();

    // Build display text for user message
    const displayText = text || '(attached files only)';

    // Add user message (with attachments indicator)
    const userMsgId = this.addMessage('user', displayText, attachments);

    // Show typing indicator
    const typingId = this.addTypingIndicator();

    // Build messages payload (include conversation history)
    const messagesPayload = this.messages
      .filter(m => m.role === 'user' || m.role === 'assistant')
      .map(m => {
        const msg = { role: m.role, content: m.content };
        if (m.attachments && m.attachments.length > 0) {
          msg.attachments = m.attachments.map(a => ({
            filename: a.filename,
            content_base64: a.content_base64,
            mime_type: a.mime_type,
          }));
        }
        return msg;
      });

    try {
      const response = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: this.modelSelect.value,
          provider: this.providerSelect.value,
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

  addMessage(role, content, attachments = []) {
    const msgId = `msg-${++this.messageCounter}`;
    const now = new Date();
    const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    this.messages.push({ role, content, id: msgId, time: timeStr, attachments });

    const wrapper = document.createElement('div');
    wrapper.className = 'message-wrapper';
    wrapper.id = msgId;

    const avatarIcon = role === 'user' ? '👤' : '🛡️';
    const roleName = role === 'user' ? 'You' : 'PromptGuard AI';

    // Build attachment chips HTML for user messages
    let attachmentHtml = '';
    if (role === 'user' && attachments.length > 0) {
      const chips = attachments.map(att => {
        const icon = getFileIcon(att.filename);
        const sizeStr = formatFileSize(att.size);
        if (att.previewUrl) {
          return `<div class="msg-attachment-chip has-preview">
            <img class="msg-attachment-thumb" src="${att.previewUrl}" alt="${this.escapeHtml(att.filename)}">
            <span class="msg-attachment-name">${this.escapeHtml(att.filename)}</span>
            <span class="msg-attachment-size">${sizeStr}</span>
          </div>`;
        }
        return `<div class="msg-attachment-chip">
          <span class="msg-attachment-icon">${icon}</span>
          <span class="msg-attachment-name">${this.escapeHtml(att.filename)}</span>
          <span class="msg-attachment-size">${sizeStr}</span>
        </div>`;
      }).join('');
      attachmentHtml = `<div class="msg-attachments">${chips}</div>`;
    }

    wrapper.innerHTML = `
      <div class="message ${role}">
        <div class="message-avatar">${avatarIcon}</div>
        <div class="message-body">
          <div class="message-role">
            ${roleName}
            <span class="message-timestamp">${timeStr}</span>
          </div>
          ${attachmentHtml}
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

    // Build media scan indicator
    const mediaScan = security.pipeline?.media_scan;
    let mediaBadge = '';
    if (mediaScan && mediaScan.total_media_items > 0) {
      const mediaCount = mediaScan.total_media_items;
      const imgCount = mediaScan.images_scanned;
      const fileCount = mediaScan.files_scanned;
      const parts = [];
      if (imgCount > 0) parts.push(`${imgCount} image${imgCount > 1 ? 's' : ''}`);
      if (fileCount > 0) parts.push(`${fileCount} file${fileCount > 1 ? 's' : ''}`);
      mediaBadge = `<span class="media-scan-badge" title="${parts.join(', ')} scanned">📎 ${mediaCount} media scanned</span>`;
    }

    container.innerHTML = `
      <div class="security-badge ${cssClass}" id="toggle-${badgeId}" title="Click to view security analysis">
        <span class="badge-icon">${icons[action]}</span>
        <span>${labels[action]}</span>
        ${mediaBadge}
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

    // Media Scan Summary Card
    let mediaScanHtml = '';
    const mediaScan = pipeline.media_scan;
    if (mediaScan && mediaScan.total_media_items > 0) {
      const extractions = mediaScan.extractions || [];
      const extractionRows = extractions.map(e => {
        const statusIcon = e.success ? '✅' : '⚠️';
        const statusText = e.success
          ? `${e.char_count} chars extracted`
          : (e.error || 'Failed');
        const typeIcon = e.source_type === 'image' ? '🖼️' : '📄';
        return `
          <div class="media-extraction-row">
            <span class="media-extraction-icon">${typeIcon}</span>
            <span class="media-extraction-name" title="${this.escapeHtml(e.filename)}">${this.escapeHtml(e.filename)}</span>
            <span class="media-extraction-method">${e.method || '—'}</span>
            <span class="media-extraction-status">${statusIcon} ${statusText}</span>
          </div>
        `;
      }).join('');

      mediaScanHtml = `
        <div class="detail-section">
          <div class="detail-title">📎 Media Scan Results</div>
          <div class="media-scan-summary">
            <div class="media-scan-stat">
              <span class="media-stat-value">${mediaScan.images_scanned}</span>
              <span class="media-stat-label">Images</span>
            </div>
            <div class="media-scan-stat">
              <span class="media-stat-value">${mediaScan.files_scanned}</span>
              <span class="media-stat-label">Files</span>
            </div>
            <div class="media-scan-stat">
              <span class="media-stat-value">${mediaScan.total_text_extracted}</span>
              <span class="media-stat-label">Chars Extracted</span>
            </div>
          </div>
          <div class="media-extractions-list">${extractionRows}</div>
        </div>
      `;
    }

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
      const entityRows = allMatches.map(m => {
        const sourceBadge = m.source === 'media'
          ? `<span class="entity-source-badge media">📎 media</span>`
          : `<span class="entity-source-badge text">💬 text</span>`;
        return `
          <div class="entity-item">
            <span class="entity-type">${this.escapeHtml(m.entity_type)}</span>
            <span class="entity-snippet" title="${this.escapeHtml(m.text_snippet)}">${this.escapeHtml(m.text_snippet)}</span>
            ${sourceBadge}
            <span class="entity-severity ${m.severity}">${m.severity}</span>
          </div>
        `;
      }).join('');

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
      ${mediaScanHtml}
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
