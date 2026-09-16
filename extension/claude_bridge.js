/**
 * PromptGuard — Claude Bridge (MAIN World)
 *
 * This script runs in the MAIN world on Claude.ai, giving it access to
 * the page's JavaScript context including ProseMirror editor instances.
 * It provides helper functions that the content script (also MAIN world)
 * can use to read/write ProseMirror content properly.
 *
 * Claude uses a ProseMirror-based contenteditable editor. Direct DOM
 * manipulation (innerText, innerHTML) does NOT update ProseMirror's
 * internal state, causing silent failures. This bridge interacts with
 * the editor through proper DOM events and execCommand to ensure state
 * consistency.
 */

(function () {
  'use strict';

  /**
   * Locate the ProseMirror editor element on Claude.ai.
   * Uses multiple fallback selectors to handle layout changes.
   */
  window.__promptguard_claude = {

    /**
     * Find the active contenteditable editor element.
     * Returns the DOM element or null.
     */
    getEditor: function () {
      // Strategy 1: ProseMirror class (most specific)
      let el = document.querySelector('.ProseMirror[contenteditable="true"]');
      if (el) return el;

      // Strategy 2: contenteditable inside the composer area
      el = document.querySelector('[data-placeholder][contenteditable="true"]');
      if (el) return el;

      // Strategy 3: contenteditable with role="textbox"
      el = document.querySelector('[role="textbox"][contenteditable="true"]');
      if (el) return el;

      // Strategy 4: fieldset contenteditable (original selector)
      el = document.querySelector('fieldset [contenteditable="true"]');
      if (el) return el;

      // Strategy 5: any contenteditable that looks like a chat input
      const allEditable = document.querySelectorAll('[contenteditable="true"]');
      for (const candidate of allEditable) {
        // Skip tiny elements (likely not the main input)
        const rect = candidate.getBoundingClientRect();
        if (rect.width > 200 && rect.height > 20) {
          return candidate;
        }
      }

      return null;
    },

    /**
     * Read the current text from the ProseMirror editor.
     */
    getText: function () {
      const editor = this.getEditor();
      if (!editor) return '';
      return editor.innerText || editor.textContent || '';
    },

    /**
     * Set text into the ProseMirror editor using proper DOM event
     * dispatching so ProseMirror's internal state stays in sync.
     */
    setText: function (text) {
      const editor = this.getEditor();
      if (!editor) return false;

      // Focus the editor first
      editor.focus();

      // Select all existing content
      const selection = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(editor);
      selection.removeAllRanges();
      selection.addRange(range);

      // Use execCommand to insert text — this goes through the browser's
      // editing pipeline and ProseMirror picks up the change.
      document.execCommand('insertText', false, text);

      // Fire input event as a fallback for frameworks listening on it
      editor.dispatchEvent(new InputEvent('input', {
        bubbles: true,
        cancelable: true,
        inputType: 'insertText',
        data: text,
      }));

      return true;
    },

    /**
     * Clear the editor content.
     */
    clear: function () {
      const editor = this.getEditor();
      if (!editor) return;

      editor.focus();
      const selection = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(editor);
      selection.removeAllRanges();
      selection.addRange(range);
      document.execCommand('delete', false, null);
    },

    /**
     * Find the Send button on Claude's interface.
     * Multiple fallback strategies.
     */
    getSendButton: function () {
      // Strategy 1: aria-label matching
      let btn = document.querySelector('button[aria-label="Send Message"]');
      if (btn && !btn.disabled) return btn;

      btn = document.querySelector('button[aria-label="Send message"]');
      if (btn && !btn.disabled) return btn;

      btn = document.querySelector('button[aria-label="Send"]');
      if (btn && !btn.disabled) return btn;

      // Strategy 2: button with send-like SVG near the input
      const allButtons = document.querySelectorAll('button');
      for (const b of allButtons) {
        const label = (b.getAttribute('aria-label') || '').toLowerCase();
        if (label.includes('send')) return b;
      }

      // Strategy 3: the last enabled button in the composer/form area
      const form = document.querySelector('form') || document.querySelector('fieldset');
      if (form) {
        const buttons = form.querySelectorAll('button:not([disabled])');
        if (buttons.length > 0) return buttons[buttons.length - 1];
      }

      return null;
    },

    /**
     * Click the send button using proper event sequences.
     */
    clickSend: function () {
      const btn = this.getSendButton();
      if (!btn) return false;

      // Full mouse event sequence for framework compatibility
      btn.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, cancelable: true }));
      btn.dispatchEvent(new MouseEvent('mouseup', { bubbles: true, cancelable: true }));
      btn.click();
      return true;
    },
  };

  console.log('[PromptGuard] Claude bridge loaded (MAIN world)');
})();
