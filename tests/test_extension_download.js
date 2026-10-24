const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync('extension/content.js', 'utf8');

function extractFunction(name) {
  const start = source.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `missing ${name}`);
  const open = source.indexOf('{', start);
  let depth = 0;
  for (let index = open; index < source.length; index++) {
    if (source[index] === '{') depth++;
    if (source[index] === '}') depth--;
    if (depth === 0) return source.slice(start, index + 1);
  }
  throw new Error(`unclosed function ${name}`);
}

function createDownloadHarness() {
  const state = { clicked: false, filename: '', closed: 0, cleared: 0 };
  const anchor = {
    style: {},
    click() { state.clicked = true; },
    remove() {},
  };
  const context = {
    atob,
    Blob,
    Uint8Array,
    URL: {
      createObjectURL() { return 'blob:test'; },
      revokeObjectURL() {},
    },
    document: {
      createElement(tag) {
        assert.equal(tag, 'a');
        return new Proxy(anchor, {
          set(target, key, value) {
            if (key === 'download') state.filename = value;
            target[key] = value;
            return true;
          },
        });
      },
      body: { appendChild() {} },
    },
    setTimeout() {},
    console: { error() {} },
    clearHeldBackAttachments() { state.cleared++; },
    removeOverlay() { state.closed++; },
  };
  vm.createContext(context);
  vm.runInContext(
    `${extractFunction('downloadSanitizedAttachment')}\n${extractFunction('downloadSanitizedAttachmentAndClose')}\nthis.run = downloadSanitizedAttachmentAndClose;`,
    context,
  );
  return { state, run: context.run };
}

test('successful sanitized download closes the blocking overlay', () => {
  const { state, run } = createDownloadHarness();
  const started = run({
    filename: 'application.pdf',
    mime_type: 'application/pdf',
    content_base64: `data:application/pdf;base64,${Buffer.from('%PDF-test').toString('base64')}`,
  }, [{ filename: 'application.pdf' }]);

  assert.equal(started, true);
  assert.equal(state.clicked, true);
  assert.equal(state.filename, 'application_sanitized.pdf');
  assert.equal(state.cleared, 1);
  assert.equal(state.closed, 1);
  assert.match(source, /downloadSanitizedAttachmentAndClose\(downloadableAttachments\[index\], attachmentsToClear\)/);
});

test('failed sanitized download keeps the overlay open', () => {
  const { state, run } = createDownloadHarness();
  const started = run({
    filename: 'application.pdf',
    content_base64: 'data:application/pdf;base64,!',
  });

  assert.equal(started, false);
  assert.equal(state.clicked, false);
  assert.equal(state.cleared, 0);
  assert.equal(state.closed, 0);
});

test('held-back attachment cleanup removes composer files and clears pending state', () => {
  const state = { removed: [], inputCleared: 0, pendingCleared: false };
  const context = {
    pendingAttachments: [{ filename: 'application.pdf' }],
    isProcessing: true,
    document: { querySelectorAll: () => [{}] },
    clearInputFiles() { state.inputCleared++; },
    clearAttachments() { state.pendingCleared = true; },
    removeComposerAttachment(filename) {
      state.removed.push(filename);
      return true;
    },
  };
  vm.createContext(context);
  vm.runInContext(`${extractFunction('clearHeldBackAttachments')}\nthis.clear = clearHeldBackAttachments;`, context);
  context.clear([{ filename: 'application.pdf' }]);

  assert.deepEqual(state.removed, ['application.pdf']);
  assert.equal(state.inputCleared, 1);
  assert.equal(state.pendingCleared, true);
  assert.equal(context.isProcessing, false);
  assert.match(source, /const dismissAndClear = \(\) => \{\s*clearHeldBackAttachments\(attachmentsToClear\);\s*removeOverlay\(\);/);
});

test('window capture routes dismissal past the page send-event guard', () => {
  const state = { dismissed: 0, stopped: 0, prevented: 0 };
  const overlay = { __promptGuardErrorActions: { dismiss() { state.dismissed++; }, download() {} } };
  const button = {
    closest(selector) {
      return selector === '.promptguard-overlay' ? overlay : this;
    },
    matches() { return false; },
  };
  const context = {};
  vm.createContext(context);
  vm.runInContext(`${extractFunction('handlePromptGuardOverlayEvent')}\nthis.handle = handlePromptGuardOverlayEvent;`, context);
  context.handle({
    type: 'click',
    target: button,
    preventDefault() { state.prevented++; },
    stopImmediatePropagation() { state.stopped++; },
  });

  assert.equal(state.dismissed, 1);
  assert.equal(state.stopped, 1);
  assert.equal(state.prevented, 1);
});
