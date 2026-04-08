const INITIAL_BINARY_ID = window.__HEADLESS_WEB_BOOT__?.initialBinaryId ?? null;
const LIVE_WS_PORT = window.__HEADLESS_WEB_BOOT__?.liveWsPort ?? null;
const LIVE_WS_URL = LIVE_WS_PORT ? `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.hostname}:${LIVE_WS_PORT}/ws` : null;
const state = {
  initialBinaryId: INITIAL_BINARY_ID,
  projects: [],
  sessions: [],
  selectedProjectId: null,
  selectedBinaryId: null,
  selectedSessionId: null,
  resourceMode: 'functions',
  activeTab: 'decompile',
  selectedItem: null,
  currentIndexState: null,
  currentSnapshots: [],
  currentResourceItems: [],
  loading: false,
  lastLiveEvent: null,
  layout: {
    sidebarWidth: 380,
    inspectorWidth: 300,
  },
  nav: {
    back: [],
    forward: [],
    current: null,
  },
  hover: {
    timer: null,
    cache: new Map(),
    activeKey: '',
  },
};
let liveSocket = null;
let liveRefreshTimer = null;

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function updateNavButtons() {
  const back = document.getElementById('navBackBtn');
  const forward = document.getElementById('navForwardBtn');
  if (back) back.disabled = state.nav.back.length === 0;
  if (forward) forward.disabled = state.nav.forward.length === 0;
}

function buildNavigationSnapshot(query = '') {
  if (!state.selectedBinaryId) return null;
  const item = state.selectedItem
    ? {
        kind: state.selectedItem.kind,
        name: state.selectedItem.name || '',
        addr: state.selectedItem.addr || '',
        query: query || state.selectedItem.addr || state.selectedItem.name || '',
      }
    : null;
  return {
    projectId: state.selectedProjectId,
    binaryId: state.selectedBinaryId,
    sessionId: state.selectedSessionId,
    resourceMode: state.resourceMode,
    activeTab: state.activeTab,
    item,
  };
}

function sameSnapshot(a, b) {
  return JSON.stringify(a || null) === JSON.stringify(b || null);
}

function commitNavigationSnapshot(snapshot, {fromHistory = false} = {}) {
  if (!snapshot) return;
  if (fromHistory) {
    state.nav.current = snapshot;
    updateNavButtons();
    return;
  }
  if (state.nav.current && !sameSnapshot(state.nav.current, snapshot)) {
    state.nav.back.push(state.nav.current);
    if (state.nav.back.length > 100) state.nav.back.shift();
    state.nav.forward = [];
  }
  state.nav.current = snapshot;
  updateNavButtons();
}

const C_KEYWORDS = new Set([
  'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'default', 'break',
  'continue', 'return', 'goto', 'sizeof', 'struct', 'union', 'enum', 'typedef',
  'const', 'static', 'volatile', 'extern', 'inline', '__fastcall', '__cdecl',
  '__stdcall', '__noreturn', '__spoils', '__usercall', '__userpurge'
]);
const C_TYPES = new Set([
  'void', 'bool', 'char', 'short', 'int', 'long', 'float', 'double', 'signed',
  'unsigned', '__int8', '__int16', '__int32', '__int64', 'size_t', 'ssize_t',
  '_byte', '_word', '_dword', '_qword', '_oword'
]);
const ASM_MNEMONICS = new Set([
  'mov', 'lea', 'push', 'pop', 'call', 'jmp', 'jz', 'jnz', 'je', 'jne', 'ja',
  'jae', 'jb', 'jbe', 'jg', 'jge', 'jl', 'jle', 'test', 'cmp', 'xor', 'or',
  'and', 'add', 'sub', 'imul', 'mul', 'idiv', 'div', 'inc', 'dec', 'nop',
  'ret', 'retn', 'leave', 'shl', 'shr', 'sar', 'rol', 'ror', 'not', 'neg',
  'cmovz', 'cmovnz', 'setz', 'setnz', 'movzx', 'movsx'
]);
const ASM_REGISTERS = /(\b(?:r(?:[0-9]|1[0-5]|[abcd]x|[sb]p|[sd]i)|e(?:[abcd]x|[sb]p|[sd]i|ip|flags)|[abcd][lh]|[cdefgs]s|[sd]s|[sb]p|[sd]i|xmm\d+|ymm\d+|zmm\d+|mm\d+|st\(\d+\)|rip|eip|rsp|esp|rbp|ebp|rax|rbx|rcx|rdx)\b)/gi;

function wrapSyntax(cls, text) {
  return `<span class="${cls}">${escapeHtml(text)}</span>`;
}

function makeJumpSpan(query, text) {
  return `<span class="syntax-jump" data-jump-query="${encodeURIComponent(query)}">${escapeHtml(text)}</span>`;
}

function isIdentifierStart(ch) {
  return /[A-Za-z_]/.test(ch);
}

function isIdentifierPart(ch) {
  return /[A-Za-z0-9_.$?@]/.test(ch);
}

function isRegisterToken(token) {
  return /^(?:r(?:[0-9]|1[0-5]|[abcd]x|[sb]p|[sd]i)|e(?:[abcd]x|[sb]p|[sd]i|ip|flags)|[abcd][lh]|[cdefgs]s|[sd]s|[sb]p|[sd]i|xmm\d+|ymm\d+|zmm\d+|mm\d+|st\(\d+\)|rip|eip|rsp|esp|rbp|ebp|rax|rbx|rcx|rdx)$/i.test(token);
}

function isJumpMnemonic(token) {
  const lower = String(token || '').toLowerCase();
  return lower === 'call' || lower === 'jmp' || /^j[a-z]+$/.test(lower);
}

function highlightPlainSegment(text, mode, options = {}) {
  const source = String(text ?? '');
  const jumpIdentifiers = options.jumpIdentifiers || false;
  const forceJump = options.forceJump || false;
  let html = '';
  let i = 0;

  while (i < source.length) {
    const ch = source[i];
    if (/\s/.test(ch)) {
      html += escapeHtml(ch);
      i += 1;
      continue;
    }

    const hexMatch = source.slice(i).match(/^0x[0-9a-fA-F]+/);
    if (hexMatch) {
      const token = hexMatch[0];
      html += forceJump ? makeJumpSpan(token, token) : `<span class="syntax-number">${token}</span>`;
      i += token.length;
      continue;
    }

    const numMatch = source.slice(i).match(/^\d+/);
    if (numMatch) {
      const token = numMatch[0];
      html += `<span class="syntax-number">${token}</span>`;
      i += token.length;
      continue;
    }

    if (isIdentifierStart(ch)) {
      let j = i + 1;
      while (j < source.length && isIdentifierPart(source[j])) j += 1;
      const token = source.slice(i, j);
      const lower = token.toLowerCase();
      let rendered = escapeHtml(token);

      if (mode === 'asm') {
        if (isRegisterToken(token)) {
          rendered = `<span class="syntax-register">${escapeHtml(token)}</span>`;
        } else if (forceJump && !ASM_MNEMONICS.has(lower)) {
          rendered = makeJumpSpan(token, token);
        }
      } else if (C_TYPES.has(token)) {
        rendered = `<span class="syntax-type">${escapeHtml(token)}</span>`;
      } else if (C_KEYWORDS.has(token)) {
        rendered = `<span class="syntax-keyword">${escapeHtml(token)}</span>`;
      } else if (jumpIdentifiers) {
        let k = j;
        while (k < source.length && /\s/.test(source[k])) k += 1;
        if (source[k] === '(') {
          rendered = makeJumpSpan(token, token);
        }
      }

      html += rendered;
      i = j;
      continue;
    }

    html += escapeHtml(ch);
    i += 1;
  }

  return html;
}

function highlightAsmOperands(text, mnemonic) {
  return highlightPlainSegment(text, 'asm', {forceJump: isJumpMnemonic(mnemonic)});
}

function highlightAsmLine(line) {
  if (!line) return '';
  let code = line;
  let comment = '';
  const commentIndex = line.indexOf(';');
  if (commentIndex >= 0) {
    code = line.slice(0, commentIndex);
    comment = line.slice(commentIndex);
  }

  let output = '';
  let rest = code;
  const labelMatch = rest.match(/^(\s*[A-Za-z_.$?@][\w.$?@]*:)(\s*)/);
  if (labelMatch) {
    output += wrapSyntax('syntax-symbol', labelMatch[1]) + escapeHtml(labelMatch[2]);
    rest = rest.slice(labelMatch[0].length);
  }

  const mnemonicMatch = rest.match(/^(\s*)([A-Za-z][A-Za-z0-9_.]{1,14})(\b)([\s\S]*)$/);
  if (mnemonicMatch && ASM_MNEMONICS.has(mnemonicMatch[2].toLowerCase())) {
    output += escapeHtml(mnemonicMatch[1]);
    output += wrapSyntax('syntax-mnemonic', mnemonicMatch[2]);
    output += highlightAsmOperands(mnemonicMatch[4], mnemonicMatch[2]);
  } else {
    output += highlightPlainSegment(rest, 'asm');
  }

  if (comment) {
    output += wrapSyntax('syntax-comment', comment);
  }
  return output;
}

function highlightCode(text, mode = 'plain') {
  const source = String(text ?? '');
  if (!source) return `<span class="syntax-plain"></span>`;
  if (mode === 'asm') {
    return source.split('\n').map((line) => highlightAsmLine(line)).join('\n');
  }

  const parts = [];
  let cursor = 0;
  while (cursor < source.length) {
    const char = source[cursor];
    const next = source[cursor + 1];
    if (char === '/' && next === '/') {
      const end = source.indexOf('\n', cursor);
      const sliceEnd = end === -1 ? source.length : end;
      parts.push({kind: 'comment', text: source.slice(cursor, sliceEnd)});
      cursor = sliceEnd;
      continue;
    }
    if (char === '/' && next === '*') {
      const end = source.indexOf('*/', cursor + 2);
      const sliceEnd = end === -1 ? source.length : end + 2;
      parts.push({kind: 'comment', text: source.slice(cursor, sliceEnd)});
      cursor = sliceEnd;
      continue;
    }
    if (char === '"' || char === "'") {
      const quote = char;
      let end = cursor + 1;
      while (end < source.length) {
        if (source[end] === '\\') {
          end += 2;
          continue;
        }
        if (source[end] === quote) {
          end += 1;
          break;
        }
        end += 1;
      }
      parts.push({kind: 'string', text: source.slice(cursor, end)});
      cursor = end;
      continue;
    }
    let end = cursor + 1;
    while (end < source.length) {
      const current = source[end];
      const following = source[end + 1];
      if ((current === '/' && (following === '/' || following === '*')) || current === '"' || current === "'") {
        break;
      }
      end += 1;
    }
    parts.push({kind: 'code', text: source.slice(cursor, end)});
    cursor = end;
  }

  return parts.map((part) => {
    if (part.kind === 'comment') return wrapSyntax('syntax-comment', part.text);
    if (part.kind === 'string') return wrapSyntax('syntax-string', part.text);
    return highlightPlainSegment(part.text, 'c', {jumpIdentifiers: true});
  }).join('');
}

function currentFunctionName() {
  return state.selectedItem?.context?.function?.name || state.selectedItem?.name || '';
}

function lineShouldHighlightAddress(line) {
  const addr = String(state.selectedItem?.addr || '').trim();
  return Boolean(addr && line.includes(addr));
}

function lineShouldHighlightFunction(line, mode) {
  if (mode !== 'c') return false;
  const name = String(currentFunctionName() || '').trim();
  if (!name || /^0x[0-9a-f]+$/i.test(name)) return false;
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`\\b${escaped}\\s*\\(`).test(line);
}

function renderCodeLines(text, mode = 'plain', error = false) {
  const source = String(text ?? '');
  const lines = source.split('\n');
  return `<div class="code-lines">${lines.map((line, index) => {
    const classes = ['code-line'];
    if (!error && lineShouldHighlightAddress(line)) classes.push('is-active-address');
    if (!error && lineShouldHighlightFunction(line, mode)) classes.push('is-active-function');
    const content = error
      ? `<span class="syntax-error">${escapeHtml(line || ' ')}</span>`
      : highlightCode(line || ' ', mode);
    return `
      <div class="${classes.join(' ')}" data-line="${index + 1}">
        <span class="code-line-number">${index + 1}</span>
        <span class="code-line-code">${content}</span>
      </div>
    `;
  }).join('')}</div>`;
}

function renderCodeBlock(elementId, text, mode = 'plain', error = false) {
  const element = document.getElementById(elementId);
  if (!element) return;
  element.innerHTML = renderCodeLines(text, mode, error);
  const activeLine = element.querySelector('.code-line.is-active-address, .code-line.is-active-function');
  if (activeLine) {
    activeLine.scrollIntoView({block: 'center', inline: 'nearest'});
  }
}

async function jumpToQuery(query) {
  if (!query) return;
  document.getElementById('gotoInput').value = query;
  await lookupAndOpen(query);
}

function onCodeBlockClick(event) {
  const target = event.target.closest('[data-jump-query]');
  if (!target) return;
  const query = decodeURIComponent(target.getAttribute('data-jump-query') || '');
  if (!query) return;
  event.preventDefault();
  event.stopPropagation();
  jumpToQuery(query);
}

function setStatus(message, meta = '', isError = false) {
  const text = document.getElementById('statusText');
  const metaEl = document.getElementById('statusMeta');
  text.textContent = message;
  metaEl.textContent = meta || '';
  document.querySelector('.statusbar').style.background = isError ? '#a1260d' : '#007acc';
}

function findPreviewTarget(node) {
  return node?.closest?.('[data-jump-query],[data-preview-query]') || null;
}

function getPreviewSpec(target) {
  if (!target) return null;
  const query = decodeURIComponent(target.getAttribute('data-preview-query') || target.getAttribute('data-jump-query') || '');
  if (!query) return null;
  return {
    query,
    kind: target.getAttribute('data-preview-kind') || 'lookup',
    label: decodeURIComponent(target.getAttribute('data-preview-label') || '') || query,
  };
}

function positionHoverPreview(x, y) {
  const preview = document.getElementById('hoverPreview');
  if (!preview || preview.classList.contains('hidden')) return;
  const margin = 14;
  const rect = preview.getBoundingClientRect();
  const left = Math.min(window.innerWidth - rect.width - margin, x + 14);
  const top = Math.min(window.innerHeight - rect.height - margin, y + 14);
  preview.style.left = `${Math.max(margin, left)}px`;
  preview.style.top = `${Math.max(margin, top)}px`;
}

function hideHoverPreview() {
  const preview = document.getElementById('hoverPreview');
  if (preview) {
    preview.classList.add('hidden');
    preview.innerHTML = '';
  }
  state.hover.activeKey = '';
  if (state.hover.timer) {
    clearTimeout(state.hover.timer);
    state.hover.timer = null;
  }
}

function renderPreviewPayload(spec, payload) {
  const normalized = unwrapResult(payload?.result ?? payload);
  const fn = extractFunctionEntry(normalized);
  const addr = findFirstAddress(normalized) || spec.query;
  const title = fn?.name || spec.label || spec.query;
  const meta = addr && addr !== title ? addr : spec.kind;
  let body = '';
  if (fn?.signature) body = fn.signature;
  else if (fn?.size) body = `size ${fn.size}`;
  else if (typeof normalized === 'string') body = normalized;
  else if (normalized?.string) body = normalized.string;
  else body = prettyJson(normalized).slice(0, 320);
  return `
    <div class='hover-preview-title'>${escapeHtml(title)}</div>
    <div class='hover-preview-meta'>${escapeHtml(meta)}</div>
    <div class='hover-preview-body'>${escapeHtml(body)}</div>
  `;
}

async function fetchPreview(spec) {
  const key = `${spec.kind}:${spec.query}`;
  if (state.hover.cache.has(key)) return state.hover.cache.get(key);
  if (!state.selectedSessionId) {
    const fallback = `
      <div class='hover-preview-title'>${escapeHtml(spec.label)}</div>
      <div class='hover-preview-meta'>No live session</div>
      <div class='hover-preview-body'>${escapeHtml(spec.query)}</div>
    `;
    state.hover.cache.set(key, fallback);
    return fallback;
  }
  try {
    const payload = await api(`/api/sessions/${state.selectedSessionId}/lookup?query=${encodeURIComponent(spec.query)}`);
    const html = renderPreviewPayload(spec, payload);
    state.hover.cache.set(key, html);
    return html;
  } catch (err) {
    const html = `
      <div class='hover-preview-title'>${escapeHtml(spec.label)}</div>
      <div class='hover-preview-meta'>Preview failed</div>
      <div class='hover-preview-body'>${escapeHtml(err.message)}</div>
    `;
    state.hover.cache.set(key, html);
    return html;
  }
}

function scheduleHoverPreview(target, event) {
  const spec = getPreviewSpec(target);
  if (!spec) return;
  hideHoverPreview();
  const key = `${spec.kind}:${spec.query}`;
  state.hover.activeKey = key;
  state.hover.timer = setTimeout(async () => {
    const preview = document.getElementById('hoverPreview');
    if (!preview || state.hover.activeKey !== key) return;
    preview.innerHTML = `
      <div class='hover-preview-title'>${escapeHtml(spec.label)}</div>
      <div class='hover-preview-meta'>Loading preview…</div>
    `;
    preview.classList.remove('hidden');
    positionHoverPreview(event.clientX, event.clientY);
    preview.innerHTML = await fetchPreview(spec);
    positionHoverPreview(event.clientX, event.clientY);
  }, 250);
}

function initHoverPreview() {
  document.addEventListener('mouseover', (event) => {
    const target = findPreviewTarget(event.target);
    if (!target) return;
    scheduleHoverPreview(target, event);
  });
  document.addEventListener('mousemove', (event) => positionHoverPreview(event.clientX, event.clientY));
  document.addEventListener('mouseout', (event) => {
    const from = findPreviewTarget(event.target);
    if (!from) return;
    const to = findPreviewTarget(event.relatedTarget);
    if (from === to) return;
    hideHoverPreview();
  });
  document.addEventListener('scroll', hideHoverPreview, true);
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: {'Content-Type': 'application/json'},
    ...options,
  });
  const text = await response.text();
  let payload = {};
  try {
    payload = text ? JSON.parse(text) : {};
  } catch (err) {
    payload = {error: text};
  }
  if (!response.ok) {
    throw new Error(payload.error || `${response.status} ${response.statusText}`);
  }
  return payload;
}

function unwrapResult(value) {
  let current = value;
  while (current && typeof current === 'object' && !Array.isArray(current) && Object.keys(current).length === 1 && Object.prototype.hasOwnProperty.call(current, 'result')) {
    current = current.result;
  }
  return current;
}

function asArray(value) {
  if (Array.isArray(value)) return value;
  if (value == null) return [];
  if (typeof value === 'object') {
    if (Array.isArray(value.data)) return value.data;
    if (Array.isArray(value.matches)) return value.matches;
    if (Array.isArray(value.items)) return value.items;
    if (Array.isArray(value.xrefs)) return value.xrefs;
    return [value];
  }
  return [value];
}

function prettyJson(value) {
  try {
    return JSON.stringify(value, null, 2);
  } catch (err) {
    return String(value);
  }
}

function formatBytes(value) {
  const size = Number(value || 0);
  if (!Number.isFinite(size) || size <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  let current = size;
  let unitIndex = 0;
  while (current >= 1024 && unitIndex < units.length - 1) {
    current /= 1024;
    unitIndex += 1;
  }
  return `${current.toFixed(current >= 10 || unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function loadLayoutPrefs() {
  try {
    const sidebar = Number(localStorage.getItem('ida-workspace.sidebar-width'));
    const inspector = Number(localStorage.getItem('ida-workspace.inspector-width'));
    if (Number.isFinite(sidebar)) state.layout.sidebarWidth = clamp(sidebar, 260, 720);
    if (Number.isFinite(inspector)) state.layout.inspectorWidth = clamp(inspector, 240, 560);
  } catch (_err) {}
}

function saveLayoutPrefs() {
  try {
    localStorage.setItem('ida-workspace.sidebar-width', String(state.layout.sidebarWidth));
    localStorage.setItem('ida-workspace.inspector-width', String(state.layout.inspectorWidth));
  } catch (_err) {}
}

function applyLayoutPrefs() {
  const root = document.documentElement;
  root.style.setProperty('--sidebar-width', `${state.layout.sidebarWidth}px`);
  root.style.setProperty('--inspector-width', `${state.layout.inspectorWidth}px`);
}

function initSplitters() {
  const app = document.querySelector('.app');
  const layout = document.querySelector('.layout');
  const left = document.getElementById('splitter-left');
  const right = document.getElementById('splitter-right');
  if (!app || !layout || !left || !right) return;

  const startDrag = (side, splitter, event) => {
    if (window.matchMedia('(max-width: 1280px)').matches && side === 'right') return;
    event.preventDefault();
    splitter.classList.add('dragging');
    app.classList.add('is-resizing');

    const onMove = (moveEvent) => {
      const rect = layout.getBoundingClientRect();
      if (side === 'left') {
        const next = clamp(moveEvent.clientX - rect.left, 260, Math.max(260, rect.width - 420));
        state.layout.sidebarWidth = next;
      } else {
        const next = clamp(rect.right - moveEvent.clientX, 240, Math.max(240, rect.width - 520));
        state.layout.inspectorWidth = next;
      }
      applyLayoutPrefs();
    };

    const onUp = () => {
      splitter.classList.remove('dragging');
      app.classList.remove('is-resizing');
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', onUp);
      saveLayoutPrefs();
    };

    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp, {once: true});
  };

  left.addEventListener('pointerdown', (event) => startDrag('left', left, event));
  right.addEventListener('pointerdown', (event) => startDrag('right', right, event));
  applyLayoutPrefs();
}

function findProject(projectId) {
  return state.projects.find((project) => project.project_id === projectId) || null;
}

function findBinary(binaryId) {
  for (const project of state.projects) {
    const binary = (project.binaries || []).find((item) => item.binary_id === binaryId);
    if (binary) return binary;
  }
  return null;
}

function findProjectIdByBinary(binaryId) {
  for (const project of state.projects) {
    if ((project.binaries || []).some((item) => item.binary_id === binaryId)) {
      return project.project_id;
    }
  }
  return null;
}

function selectedProject() {
  return findProject(state.selectedProjectId);
}

function selectedBinary() {
  return findBinary(state.selectedBinaryId);
}

function selectedSessionRecord() {
  return state.sessions.find((session) => session.runtime_session_id === state.selectedSessionId) || null;
}

function syncSelectedSession() {
  const live = state.sessions.find((session) => session.binary_id === state.selectedBinaryId && session.live);
  state.selectedSessionId = live ? live.runtime_session_id : null;
}

function renderWorkspaceMeta() {
  const project = selectedProject();
  const binary = selectedBinary();
  const session = selectedSessionRecord();
  const metadata = session?.metadata || {};
  const sessionMode = session?.session_mode || (metadata.snapshot_of ? 'snapshot' : session?.live ? 'primary' : 'idle');
  const items = [
    ['Project', project ? project.name : '—'],
    ['Binary', binary ? binary.display_name : '—'],
    ['Session', state.selectedSessionId || '—'],
    ['Mode', session ? sessionMode : '—'],
    ['Path', binary ? (binary.idb_path || binary.binary_path) : '—'],
  ];
  if (metadata.snapshot_of) {
    items.push(['Snapshot Of', metadata.snapshot_of]);
  }
  if ((session?.reuse_count || 0) > 0) {
    items.push(['Reuse Count', String(session.reuse_count)]);
  }
  document.getElementById('workspaceMeta').innerHTML = items.map(([label, value]) => `
    <div class='summary-chip'>
      <div class='label'>${escapeHtml(label)}</div>
      <div class='value'>${escapeHtml(value)}</div>
    </div>
  `).join('');
  document.getElementById('selectionPill').textContent = binary
    ? `${binary.display_name}${state.selectedSessionId ? ` · ${sessionMode}` : ' · no session'}`
    : 'No binary selected';
  const badge = document.getElementById('sessionBadge');
  if (session && session.live) {
    badge.textContent = sessionMode === 'snapshot' ? 'Snapshot session' : 'Live session';
    badge.className = 'badge success';
  } else {
    badge.textContent = 'No live session';
    badge.className = 'badge warn';
  }
}

function renderProjectTree() {
  const container = document.getElementById('projectTree');
  if (!state.projects.length) {
    container.innerHTML = `<div class='empty'>Create a project to get started.</div>`;
    return;
  }
  container.innerHTML = '';
  for (const project of state.projects) {
    const projectEl = document.createElement('div');
    projectEl.className = `tree-project${project.project_id === state.selectedProjectId ? ' active' : ''}`;
    projectEl.innerHTML = `
      <div class='row' style='justify-content:space-between;'>
        <strong>${escapeHtml(project.name)}</strong>
        <span class='badge'>${project.binary_count} bin</span>
      </div>
      <div class='small'>${escapeHtml(project.root_dir || '')}</div>
    `;
    projectEl.onclick = () => selectProject(project.project_id);
    container.appendChild(projectEl);

    const binariesWrap = document.createElement('div');
    binariesWrap.className = 'tree-binaries';
    for (const binary of project.binaries || []) {
      const isActive = binary.binary_id === state.selectedBinaryId;
      const hasLive = state.sessions.some((session) => session.binary_id === binary.binary_id && session.live);
      const activeSession = binary.active_session || null;
      const binaryEl = document.createElement('div');
      binaryEl.className = `tree-binary${isActive ? ' active' : ''}`;
      binaryEl.innerHTML = `
        <div class='row' style='justify-content:space-between;'>
          <span>${escapeHtml(binary.display_name)}</span>
          <span class='badge ${hasLive ? 'success' : ''}'>${hasLive ? (activeSession?.session_mode === 'snapshot' ? 'snapshot' : 'live') : 'idle'}</span>
        </div>
        <div class='small mono'>${escapeHtml(binary.idb_path || binary.binary_path)}</div>
        <div class='row wrap' style='margin-top:6px;'>
          <span class='badge'>${escapeHtml(binary.snapshot_count || 0)} snapshot</span>
          ${(activeSession?.reuse_count || 0) > 0 ? `<span class='badge'>reused ${escapeHtml(activeSession.reuse_count)}x</span>` : ''}
        </div>
      `;
      binaryEl.onclick = () => selectBinary(project.project_id, binary.binary_id);
      binariesWrap.appendChild(binaryEl);
    }
    container.appendChild(binariesWrap);
  }
}

function renderIndexBadges() {
  const stateInfo = state.currentIndexState || {};
  const container = document.getElementById('indexBadges');
  const badges = [
    ['funcs', stateInfo.functions_refreshed_at],
    ['strings', stateInfo.strings_refreshed_at],
    ['structs', stateInfo.structs_refreshed_at],
  ];
  container.innerHTML = badges.map(([label, value]) => `<span class='badge ${value ? 'success' : ''}'>${label}: ${escapeHtml(value ? new Date(value).toLocaleTimeString() : '—')}</span>`).join('');
}

function selectedContext() {
  return state.selectedItem?.context || {};
}

function renderInspector() {
  const binary = selectedBinary();
  const item = state.selectedItem;
  const ctx = selectedContext();
  const session = selectedSessionRecord();
  const rows = [
    ['Kind', item?.kind || '—'],
    ['Name', item?.name || '—'],
    ['Address', item?.addr || '—'],
    ['Binary', binary?.display_name || '—'],
    ['Session', state.selectedSessionId || '—'],
    ['Session mode', session?.session_mode || '—'],
    ['Live event', state.lastLiveEvent ? `${state.lastLiveEvent.operation_type || state.lastLiveEvent.event} @ ${state.lastLiveEvent.target || '—'}` : '—'],
  ];
  if ((session?.reuse_count || 0) > 0) {
    rows.push(['Reuse count', String(session.reuse_count)]);
  }
  if (session?.snapshot_of) {
    rows.push(['Snapshot of', session.snapshot_of]);
  }
  if (item?.kind === 'function' || ctx.kind === 'function') {
    rows.push(
      ['Prototype', ctx.prototype || '—'],
      ['Size', ctx.function?.size || item?.raw?.size || '—'],
      ['Callers', String((ctx.callers || []).length || 0)],
      ['Callees', String((ctx.callees || []).length || 0)],
      ['Strings', String((ctx.strings || []).length || 0)],
      ['Comments', String(ctx.comment_count || 0)],
    );
  } else if (item?.kind === 'string' || ctx.kind === 'string') {
    rows.push(
      ['Length', String((ctx.value || item?.raw?.string || '').length || 0)],
      ['Ref funcs', String(ctx.ref_function_count || 0)],
      ['Incoming refs', String((ctx.incoming_refs || []).length || 0)],
      ['Outgoing refs', String((ctx.outgoing_refs || []).length || 0)],
    );
  } else if (item?.kind === 'struct') {
    rows.push(
      ['Size', item?.raw?.size || '—'],
      ['Members', item?.raw?.members || item?.raw?.cardinality || '—'],
    );
  }
  document.getElementById('inspectorSummary').innerHTML = rows.map(([label, value]) => `
    <div class='label'>${escapeHtml(label)}</div>
    <div class='value mono'>${escapeHtml(value)}</div>
  `).join('');
  document.getElementById('renameInput').value = item?.name && !String(item.name).startsWith('0x') ? item.name : '';
}

function renderDetails(value) {
  document.getElementById('detailsOutput').textContent = prettyJson(value);
}

function renderSnapshots() {
  const container = document.getElementById('snapshotList');
  if (!state.selectedBinaryId) {
    container.innerHTML = `<div class='empty'>Select a binary.</div>`;
    return;
  }
  if (!state.currentSnapshots.length) {
    container.innerHTML = `<div class='empty'>No snapshots for this binary.</div>`;
    return;
  }
  container.innerHTML = state.currentSnapshots.map((snapshot) => `
    <div class='list-item'>
      <div class='row' style='justify-content:space-between;'>
        <strong class='mono'>${escapeHtml(snapshot.name)}</strong>
        <span class='badge ${snapshot.in_use ? 'success' : ''}'>${snapshot.in_use ? 'in use' : 'snapshot'}</span>
      </div>
      <div class='small mono'>${escapeHtml(snapshot.path)}</div>
      <div class='row wrap' style='margin-top:8px;justify-content:space-between;'>
        <span class='small'>${escapeHtml(snapshot.updated_at)} · ${escapeHtml(formatBytes(snapshot.size))}</span>
        <button ${snapshot.in_use ? 'disabled' : ''} data-snapshot-path="${escapeHtml(snapshot.path)}" onclick="deleteSnapshotWorkspace(this.dataset.snapshotPath)">Delete</button>
      </div>
    </div>
  `).join('');
}

function renderResourceButtons() {
  for (const mode of ['functions', 'strings', 'structs', 'history']) {
    const button = document.getElementById(`resource-${mode}`);
    button.classList.toggle('active', state.resourceMode === mode);
  }
}

function renderTabButtons() {
  for (const tab of ['decompile', 'disasm', 'strings', 'structs', 'history']) {
    const button = document.getElementById(`tab-${tab}`);
    const pane = document.getElementById(`view-${tab}`);
    button.classList.toggle('active', state.activeTab === tab);
    pane.classList.toggle('active', state.activeTab === tab);
  }
}

function setTab(tab) {
  state.activeTab = tab;
  renderTabButtons();
}

function setResourceMode(mode) {
  state.resourceMode = mode;
  renderResourceButtons();
  if (mode === 'strings' || mode === 'structs' || mode === 'history') {
    setTab(mode);
  }
  refreshResourcePane();
}

function onResourceFilterChange() {
  window.clearTimeout(window.__resourceFilterTimer);
  window.__resourceFilterTimer = window.setTimeout(() => refreshResourcePane(), 160);
}

async function selectProject(projectId) {
  state.selectedProjectId = projectId;
  const project = selectedProject();
  state.selectedBinaryId = project?.binaries?.[0]?.binary_id || null;
  syncSelectedSession();
  state.selectedItem = null;
  await refreshWorkspaceView();
}

async function selectBinary(projectId, binaryId) {
  state.selectedProjectId = projectId;
  state.selectedBinaryId = binaryId;
  syncSelectedSession();
  state.selectedItem = null;
  await refreshWorkspaceView();
}

async function refreshWorkspace() {
  const [projectsPayload, sessionsPayload] = await Promise.all([
    api('/api/projects'),
    api('/api/sessions'),
  ]);
  state.projects = projectsPayload.projects || [];
  state.sessions = sessionsPayload.sessions || [];

  if (state.initialBinaryId && findBinary(state.initialBinaryId)) {
    state.selectedBinaryId = state.initialBinaryId;
    state.selectedProjectId = findProjectIdByBinary(state.initialBinaryId);
    state.initialBinaryId = null;
  }

  if (state.selectedProjectId && !findProject(state.selectedProjectId)) {
    state.selectedProjectId = null;
  }
  if (state.selectedBinaryId && !findBinary(state.selectedBinaryId)) {
    state.selectedBinaryId = null;
  }

  if (!state.selectedProjectId && state.selectedBinaryId) {
    state.selectedProjectId = findProjectIdByBinary(state.selectedBinaryId);
  }
  if (!state.selectedProjectId && state.projects.length) {
    state.selectedProjectId = state.projects[0].project_id;
  }
  if (!state.selectedBinaryId) {
    const project = selectedProject();
    state.selectedBinaryId = project?.binaries?.[0]?.binary_id || null;
  }

  syncSelectedSession();
  renderProjectTree();
  await refreshWorkspaceView();
}

async function refreshWorkspaceView() {
  renderWorkspaceMeta();
  renderProjectTree();
  renderInspector();
  renderResourceButtons();
  renderTabButtons();
  await loadIndexState();
  await loadSnapshots();
  await refreshResourcePane();
}

async function loadIndexState() {
  if (!state.selectedBinaryId) {
    state.currentIndexState = null;
    renderIndexBadges();
    return;
  }
  const payload = await api(`/api/binaries/${state.selectedBinaryId}/indexes`);
  state.currentIndexState = payload.index_state || null;
  renderIndexBadges();
}

async function loadSnapshots() {
  if (!state.selectedBinaryId) {
    state.currentSnapshots = [];
    renderSnapshots();
    return;
  }
  const payload = await api(`/api/binaries/${state.selectedBinaryId}/snapshots`);
  state.currentSnapshots = payload.snapshots || [];
  renderSnapshots();
}

async function createProject() {
  const name = document.getElementById('projectName').value.trim();
  if (!name) return setStatus('Project name is required.', '', true);
  const payload = await api('/api/projects', {method: 'POST', body: JSON.stringify({name})});
  state.selectedProjectId = payload.project.project_id;
  document.getElementById('projectName').value = '';
  setStatus(`Created project ${payload.project.name}`);
  await refreshWorkspace();
}

async function addBinary() {
  if (!state.selectedProjectId) return setStatus('Select or create a project first.', '', true);
  const binaryPath = document.getElementById('artifactPath').value.trim();
  if (!binaryPath) return setStatus('Binary path is required.', '', true);
  const payload = await api(`/api/projects/${state.selectedProjectId}/binaries`, {method: 'POST', body: JSON.stringify({binary_path: binaryPath})});
  state.selectedBinaryId = payload.binary.binary_id;
  document.getElementById('artifactPath').value = '';
  setStatus(`Added ${payload.binary.display_name}`);
  await refreshWorkspace();
}

async function restoreArtifact() {
  if (!state.selectedProjectId) return setStatus('Select or create a project first.', '', true);
  const artifactPath = document.getElementById('artifactPath').value.trim();
  if (!artifactPath) return setStatus('Artifact path is required.', '', true);
  const payload = await api(`/api/projects/${state.selectedProjectId}/restore-artifact`, {method: 'POST', body: JSON.stringify({artifact_path: artifactPath})});
  state.selectedBinaryId = payload.binary.binary_id;
  document.getElementById('artifactPath').value = '';
  setStatus(`Restored ${payload.binary.display_name}`);
  await refreshWorkspace();
}

async function openSession() {
  if (!state.selectedBinaryId) return setStatus('Select a binary first.', '', true);
  const payload = await api(`/api/binaries/${state.selectedBinaryId}/sessions`, {method: 'POST'});
  state.selectedSessionId = payload.session.runtime_session_id;
  const modeMeta = payload.session?.session_mode === 'snapshot'
    ? 'snapshot session'
    : payload.reused
      ? 'reused existing session'
      : 'fresh session';
  setStatus(payload.reused ? 'Session reused.' : 'Session started.', `${payload.session.runtime_session_id} · ${modeMeta}`);
  await refreshWorkspace();
  await refreshIndexes(true);
}

async function refreshIndexes(quiet = false) {
  if (!state.selectedBinaryId) return setStatus('Select a binary first.', '', true);
  const payload = await api(`/api/binaries/${state.selectedBinaryId}/refresh-indexes`, {
    method: 'POST',
    body: JSON.stringify({session_id: state.selectedSessionId}),
  });
  state.selectedSessionId = payload.session_id || state.selectedSessionId;
  if (!quiet) {
    setStatus('Indexes refreshed.', `funcs ${payload.counts.functions} · strings ${payload.counts.strings} · structs ${payload.counts.structs}`);
  }
  await refreshWorkspace();
}

async function deleteSnapshotWorkspace(snapshotPath) {
  if (!state.selectedBinaryId) return;
  await api(`/api/binaries/${state.selectedBinaryId}/snapshots`, {
    method: 'DELETE',
    body: JSON.stringify({path: snapshotPath}),
  });
  setStatus('Snapshot deleted.', snapshotPath);
  await refreshWorkspace();
}

function summarizeFunction(item) {
  const parts = [];
  if (item.size != null) parts.push(`size ${item.size}`);
  if (item.segment) parts.push(item.segment);
  return parts.join(' · ');
}

function summarizeStruct(item) {
  const parts = [];
  if (item.size != null) parts.push(`size ${item.size}`);
  if (item.members != null) parts.push(`members ${item.members}`);
  return parts.join(' · ');
}

function renderResourceList(items, formatter, clickHandler, emptyMessage) {
  const container = document.getElementById('resourceList');
  container.innerHTML = '';
  if (!items.length) {
    container.innerHTML = `<div class='empty'>${escapeHtml(emptyMessage)}</div>`;
    return;
  }
  items.forEach((item) => {
    const el = document.createElement('div');
    const active = state.selectedItem && state.selectedItem.kind === item.__kind && state.selectedItem.addr === item.addr && state.selectedItem.name === item.name;
    el.className = `list-item${active ? ' active' : ''}`;
    el.dataset.previewKind = item.__kind || 'lookup';
    el.dataset.previewQuery = item.addr || item.name || '';
    el.dataset.previewLabel = item.name || item.addr || item.__kind || 'item';
    el.innerHTML = formatter(item);
    el.onclick = () => clickHandler(item);
    container.appendChild(el);
  });
}

function renderStringsTable(items) {
  const container = document.getElementById('stringsTable');
  if (!items.length) {
    container.innerHTML = `<div class='empty'>No cached strings yet. Refresh indexes first.</div>`;
    return;
  }
  const wrap = document.createElement('div');
  wrap.className = 'table';
  wrap.innerHTML = `<div class='table-header'><div>Address</div><div>String</div></div>`;
  items.forEach((item) => {
    const row = document.createElement('div');
    const active = state.selectedItem && state.selectedItem.kind === 'string' && state.selectedItem.addr === item.addr;
    row.className = `table-row${active ? ' active' : ''}`;
    row.dataset.previewKind = 'string';
    row.dataset.previewQuery = item.addr || item.string || '';
    row.dataset.previewLabel = item.addr || 'string';
    row.innerHTML = `<div class='mono'>${escapeHtml(item.addr || '—')}</div><div>${escapeHtml(item.string || '')}</div>`;
    row.onclick = () => selectString(item);
    wrap.appendChild(row);
  });
  container.innerHTML = '';
  container.appendChild(wrap);
}

function renderStructsTable(items) {
  const container = document.getElementById('structsTable');
  if (!items.length) {
    container.innerHTML = `<div class='empty'>No cached structs yet. Refresh indexes after analysis changes.</div>`;
    return;
  }
  const wrap = document.createElement('div');
  wrap.className = 'table';
  wrap.innerHTML = `<div class='table-header'><div>Name</div><div>Details</div></div>`;
  items.forEach((item) => {
    const row = document.createElement('div');
    const active = state.selectedItem && state.selectedItem.kind === 'struct' && state.selectedItem.name === item.name;
    row.className = `table-row${active ? ' active' : ''}`;
    row.dataset.previewKind = 'struct';
    row.dataset.previewQuery = item.name || '';
    row.dataset.previewLabel = item.name || 'struct';
    row.innerHTML = `<div class='mono'>${escapeHtml(item.name || '—')}</div><div>${escapeHtml(summarizeStruct(item) || 'Struct')}</div>`;
    row.onclick = () => selectStruct(item);
    wrap.appendChild(row);
  });
  container.innerHTML = '';
  container.appendChild(wrap);
}

function renderHistoryTable(items) {
  const container = document.getElementById('historyTable');
  if (!items.length) {
    container.innerHTML = `<div class='empty'>No history recorded for this binary yet.</div>`;
    return;
  }
  container.innerHTML = items.map((item) => `
    <div class='panel' style='margin-bottom:10px;'>
      <div class='panel-body'>
        <div class='row' style='justify-content:space-between;'>
          <strong>${escapeHtml(item.operation_type)}</strong>
          <span class='small'>${escapeHtml(item.created_at || '')}</span>
        </div>
        <div class='small'>target: ${escapeHtml(item.target || '—')}</div>
        <pre style='margin-top:8px;'>${escapeHtml(prettyJson(item.payload || item.result || {}))}</pre>
      </div>
    </div>
  `).join('');
}

function extractTextBlock(value) {
  const current = unwrapResult(value);
  if (current == null) return 'No data.';
  if (typeof current === 'string') return current;
  if (Array.isArray(current)) {
    if (current.every((item) => typeof item === 'string')) return current.join('\n');
    return current.map((item) => {
      if (typeof item === 'string') return item;
      if (item.line) return item.line;
      if (item.text) return item.text;
      if (item.disasm) return item.disasm;
      if (item.address || item.addr) return `${item.address || item.addr} ${item.text || item.disasm || ''}`.trim();
      return prettyJson(item);
    }).join('\n');
  }
  if (typeof current === 'object') {
    if (typeof current.code === 'string') return current.code;
    if (Array.isArray(current.pseudocode)) return current.pseudocode.join('\n');
    if (typeof current.pseudocode === 'string') return current.pseudocode;
    if (Array.isArray(current.lines)) {
      return current.lines.map((line) => typeof line === 'string' ? line : (line.line || line.text || prettyJson(line))).join('\n');
    }
    if (current.asm && Array.isArray(current.asm.lines)) {
      return current.asm.lines
        .map((line) => `${line.addr || ''} ${line.instruction || line.text || ''}`.trim())
        .join('\n');
    }
    if (Array.isArray(current.instructions)) {
      return current.instructions.map((insn) => {
        const addr = insn.address || insn.addr || insn.ea || '';
        const text = insn.text || insn.disasm || [insn.mnemonic, insn.operands].filter(Boolean).join(' ');
        return `${addr} ${text}`.trim();
      }).join('\n');
    }
    if (typeof current.text === 'string') return current.text;
  }
  return prettyJson(current);
}

function findFirstAddress(value) {
  const current = unwrapResult(value);
  if (typeof current === 'string' && /^0x[0-9a-f]+$/i.test(current.trim())) return current.trim();
  if (Array.isArray(current)) {
    for (const item of current) {
      const found = findFirstAddress(item);
      if (found) return found;
    }
    return null;
  }
  if (current && typeof current === 'object') {
    for (const key of ['addr', 'address', 'ea', 'start_ea']) {
      if (current[key]) return String(current[key]);
    }
    for (const value of Object.values(current)) {
      const found = findFirstAddress(value);
      if (found) return found;
    }
  }
  return null;
}

function extractFunctionEntry(value) {
  const current = unwrapResult(value);
  if (Array.isArray(current)) {
    for (const item of current) {
      if (item && typeof item === 'object' && item.fn) return item.fn;
    }
    return null;
  }
  if (current && typeof current === 'object' && current.fn) {
    return current.fn;
  }
  return null;
}

async function refreshResourcePane() {
  if (!state.selectedBinaryId) {
    document.getElementById('resourceList').innerHTML = `<div class='empty'>Select a binary to browse cached analysis.</div>`;
    document.getElementById('stringsTable').innerHTML = `<div class='empty'>Select a binary first.</div>`;
    document.getElementById('structsTable').innerHTML = `<div class='empty'>Select a binary first.</div>`;
    document.getElementById('historyTable').innerHTML = `<div class='empty'>Select a binary first.</div>`;
    return;
  }
  const filter = document.getElementById('resourceFilter').value.trim();
  if (state.resourceMode === 'functions') {
    const payload = await api(`/api/binaries/${state.selectedBinaryId}/functions?filter=${encodeURIComponent(filter)}&limit=200`);
    state.currentResourceItems = (payload.functions || []).map((item) => ({...item, __kind: 'function'}));
    renderResourceList(
      state.currentResourceItems,
      (item) => `<div class='row' style='justify-content:space-between;'><strong>${escapeHtml(item.name || item.addr || 'function')}</strong><span class='badge mono'>${escapeHtml(item.addr || '')}</span></div><div class='small'>${escapeHtml(summarizeFunction(item) || 'Function')}</div>`,
      selectFunction,
      'No cached functions yet. Start a session and refresh indexes.'
    );
    return;
  }
  if (state.resourceMode === 'strings') {
    const payload = await api(`/api/binaries/${state.selectedBinaryId}/strings?filter=${encodeURIComponent(filter)}&limit=200`);
    state.currentResourceItems = (payload.strings || []).map((item) => ({...item, __kind: 'string'}));
    renderResourceList(
      state.currentResourceItems,
      (item) => `<div class='row' style='justify-content:space-between;'><span class='mono'>${escapeHtml(item.addr || '')}</span></div><div>${escapeHtml(item.string || '')}</div>`,
      selectString,
      'No cached strings yet. Refresh indexes first.'
    );
    renderStringsTable(state.currentResourceItems);
    return;
  }
  if (state.resourceMode === 'structs') {
    const payload = await api(`/api/binaries/${state.selectedBinaryId}/structs?filter=${encodeURIComponent(filter)}&limit=200`);
    state.currentResourceItems = (payload.structs || []).map((item) => ({...item, __kind: 'struct'}));
    renderResourceList(
      state.currentResourceItems,
      (item) => `<div class='row' style='justify-content:space-between;'><strong>${escapeHtml(item.name || 'struct')}</strong></div><div class='small'>${escapeHtml(summarizeStruct(item) || 'Struct')}</div>`,
      selectStruct,
      'No cached structs yet.'
    );
    renderStructsTable(state.currentResourceItems);
    return;
  }
  const payload = await api(`/api/binaries/${state.selectedBinaryId}/history?limit=100`);
  state.currentResourceItems = (payload.operations || []).map((item) => ({...item, __kind: 'history'}));
  renderResourceList(
    state.currentResourceItems,
    (item) => `<div class='row' style='justify-content:space-between;'><strong>${escapeHtml(item.operation_type || 'event')}</strong><span class='small'>${escapeHtml(item.created_at || '')}</span></div><div class='small'>${escapeHtml(item.target || '')}</div>`,
    selectHistoryEntry,
    'No history yet.'
  );
  renderHistoryTable(state.currentResourceItems);
}

async function selectFunction(item, options = {}) {
  state.selectedItem = {
    kind: 'function',
    name: item.name || item.addr || 'function',
    addr: item.addr || '',
    raw: item,
  };
  document.getElementById('gotoInput').value = item.addr || item.name || '';
  renderInspector();
  renderDetails(item);
  await refreshResourcePane();
  setTab('decompile');
  await loadSelectionContext();
  await Promise.all([loadDecompiler(item.addr), loadDisasm(item.addr), loadXrefs(item.addr)]);
  commitNavigationSnapshot(buildNavigationSnapshot(item.addr || item.name || ''), options);
}

async function selectString(item, options = {}) {
  state.selectedItem = {
    kind: 'string',
    name: item.string || item.addr || 'string',
    addr: item.addr || '',
    raw: item,
  };
  document.getElementById('gotoInput').value = item.addr || '';
  renderInspector();
  renderDetails(item);
  await refreshResourcePane();
  setTab('strings');
  await loadSelectionContext();
  await loadXrefs(item.addr);
  commitNavigationSnapshot(buildNavigationSnapshot(item.addr || item.name || ''), options);
}

async function selectStruct(item, options = {}) {
  state.selectedItem = {
    kind: 'struct',
    name: item.name || 'struct',
    addr: item.addr || '',
    raw: item,
  };
  renderInspector();
  renderDetails(item);
  await refreshResourcePane();
  setTab('structs');
  document.getElementById('xrefsList').innerHTML = `<div class='empty'>Cross references are address-based; select a function or string to inspect xrefs.</div>`;
  commitNavigationSnapshot(buildNavigationSnapshot(item.name || ''), options);
}

function selectHistoryEntry(item, options = {}) {
  state.selectedItem = {
    kind: 'history',
    name: item.operation_type || 'history',
    addr: item.target || '',
    raw: item,
  };
  renderInspector();
  renderDetails(item);
  refreshResourcePane();
  setTab('history');
  commitNavigationSnapshot(buildNavigationSnapshot(item.target || item.operation_type || ''), options);
}

async function lookupAndOpen(explicitQuery = '', options = {}) {
  const query = explicitQuery || document.getElementById('gotoInput').value.trim();
  if (!query) return setStatus('Enter an address or symbol.', '', true);
  if (!state.selectedSessionId) return setStatus('Start a session first.', '', true);
  const payload = await api(`/api/sessions/${state.selectedSessionId}/lookup?query=${encodeURIComponent(query)}`);
  const normalized = unwrapResult(payload.result ?? payload);
  const fn = extractFunctionEntry(normalized);
  const addr = findFirstAddress(normalized) || query;
  state.selectedItem = {
    kind: fn ? 'function' : 'lookup',
    name: fn?.name || query,
    addr,
    raw: fn || normalized,
  };
  renderInspector();
  renderDetails(normalized);
  setStatus('Resolved symbol/address.', addr);
  if (/^0x[0-9a-f]+$/i.test(addr)) {
    await loadSelectionContext();
    await Promise.all([loadDecompiler(addr), loadDisasm(addr), loadXrefs(addr)]);
    setTab('decompile');
  }
  commitNavigationSnapshot(buildNavigationSnapshot(query), options);
}

async function restoreNavigationSnapshot(snapshot) {
  if (!snapshot) return;
  const binaryChanged = state.selectedBinaryId !== snapshot.binaryId || state.selectedProjectId !== snapshot.projectId;
  state.selectedProjectId = snapshot.projectId;
  state.selectedBinaryId = snapshot.binaryId;
  state.selectedSessionId = snapshot.sessionId || state.selectedSessionId;
  state.resourceMode = snapshot.resourceMode || state.resourceMode;
  state.activeTab = snapshot.activeTab || state.activeTab;

  if (binaryChanged) {
    await refreshWorkspace();
  } else {
    renderWorkspaceMeta();
    renderProjectTree();
    renderResourceButtons();
    renderTabButtons();
  }

  if (!snapshot.item) {
    state.selectedItem = null;
    renderInspector();
    commitNavigationSnapshot(snapshot, {fromHistory: true});
    return;
  }

  const item = snapshot.item;
  if (item.kind === 'function') {
    await selectFunction({name: item.name, addr: item.addr}, {fromHistory: true});
  } else if (item.kind === 'string') {
    await selectString({name: item.name, string: item.name, addr: item.addr}, {fromHistory: true});
  } else if (item.kind === 'struct') {
    await selectStruct({name: item.name, addr: item.addr}, {fromHistory: true});
  } else if (item.kind === 'history') {
    selectHistoryEntry({operation_type: item.name, target: item.addr}, {fromHistory: true});
  } else {
    await lookupAndOpen(item.query || item.addr || item.name || '', {fromHistory: true});
  }
  commitNavigationSnapshot(snapshot, {fromHistory: true});
}

async function navigateHistory(direction) {
  const source = direction === 'back' ? state.nav.back : state.nav.forward;
  const target = source.pop();
  if (!target) {
    updateNavButtons();
    return;
  }
  const current = buildNavigationSnapshot();
  if (current) {
    const other = direction === 'back' ? state.nav.forward : state.nav.back;
    other.push(current);
  }
  await restoreNavigationSnapshot(target);
  updateNavButtons();
}

async function loadContext(kind, query) {
  if (!state.selectedSessionId || !query) return null;
  const payload = await api(`/api/sessions/${state.selectedSessionId}/context?kind=${encodeURIComponent(kind)}&query=${encodeURIComponent(query)}`);
  return unwrapResult(payload.result ?? payload);
}

async function loadSelectionContext() {
  if (!state.selectedItem) return;
  try {
    let context = null;
    if (state.selectedItem.kind === 'function') {
      context = await loadContext('function', state.selectedItem.addr || state.selectedItem.name || '');
    } else if (state.selectedItem.kind === 'string') {
      context = await loadContext('string', state.selectedItem.addr || '');
    } else if (state.selectedItem.kind === 'lookup' && state.selectedItem.addr) {
      context = await loadContext('function', state.selectedItem.addr);
    } else {
      return await loadLookupDetails(state.selectedItem.addr || state.selectedItem.name || '');
    }
    if (context) {
      state.selectedItem.context = context;
      if (context.function?.name) state.selectedItem.name = context.function.name;
      if (context.resolved_addr) state.selectedItem.addr = context.resolved_addr;
      renderDetails(context);
      renderInspector();
    }
  } catch (err) {
    renderDetails({error: err.message});
  }
}

async function loadLookupDetails(query) {
  if (!state.selectedSessionId || !query) return;
  try {
    const payload = await api(`/api/sessions/${state.selectedSessionId}/lookup?query=${encodeURIComponent(query)}`);
    const normalized = unwrapResult(payload.result ?? payload);
    if (state.selectedItem) state.selectedItem.raw = normalized;
    renderDetails(normalized);
    renderInspector();
  } catch (err) {
    renderDetails({error: `Lookup failed: ${err.message}`});
  }
}

async function loadDecompiler(addr) {
  if (!state.selectedSessionId || !addr) {
    renderCodeBlock('decompileOutput', 'Start a session and select a function to view pseudocode.');
    return;
  }
  try {
    const payload = await api(`/api/sessions/${state.selectedSessionId}/decompile?addr=${encodeURIComponent(addr)}`);
    renderCodeBlock('decompileOutput', extractTextBlock(payload.result ?? payload), 'c');
  } catch (err) {
    renderCodeBlock('decompileOutput', `Decompiler error: ${err.message}`, 'plain', true);
  }
}

async function loadDisasm(addr) {
  if (!state.selectedSessionId || !addr) {
    renderCodeBlock('disasmOutput', 'Start a session and select a function to view disassembly.');
    return;
  }
  try {
    const payload = await api(`/api/sessions/${state.selectedSessionId}/disasm?addr=${encodeURIComponent(addr)}`);
    renderCodeBlock('disasmOutput', extractTextBlock(payload.result ?? payload), 'asm');
  } catch (err) {
    renderCodeBlock('disasmOutput', `Disassembly error: ${err.message}`, 'plain', true);
  }
}

function normalizeXrefBuckets(value) {
  const current = unwrapResult(value);

  if (Array.isArray(current)) {
    if (current.length && current[0] && typeof current[0] === 'object' && Array.isArray(current[0].data)) {
      return normalizeXrefBuckets(current[0]);
    }
    if (current.length && current[0] && typeof current[0] === 'object' && Array.isArray(current[0].xrefs)) {
      return {to: current[0].xrefs || [], from: []};
    }
  }

  if (current && typeof current === 'object') {
    if (Array.isArray(current.incoming) || Array.isArray(current.outgoing) || Array.isArray(current.callers) || Array.isArray(current.callees)) {
      return {
        to: current.incoming || [],
        from: current.outgoing || [],
        refFunctions: current.ref_functions || [],
        callers: current.callers || [],
        callees: current.callees || [],
        total: current.total || 0,
        resolvedAddr: current.resolved_addr || null,
      };
    }
    if (Array.isArray(current.data)) {
      return {
        to: current.data.filter((item) => item.direction === 'to'),
        from: current.data.filter((item) => item.direction === 'from'),
        refFunctions: [],
        callers: [],
        callees: [],
        total: current.total,
        resolvedAddr: current.resolved_addr || current.query || null,
      };
    }
    if (Array.isArray(current.xrefs)) {
      return {to: current.xrefs || [], from: [], refFunctions: [], callers: [], callees: []};
    }
  }

  return {to: [], from: [], refFunctions: [], callers: [], callees: [], total: 0, resolvedAddr: null};
}

function xrefRowAddress(item, direction) {
  if (direction === 'to') return item.from || item.addr || item.address || item.ea || findFirstAddress(item);
  return item.to || item.addr || item.address || item.ea || findFirstAddress(item);
}

function xrefRowSummary(item, direction) {
  const fn = item.fn;
  const fnName = typeof fn === 'string' ? fn : (fn?.name || fn?.addr || '');
  const type = item.type || item.kind || 'xref';
  const site = direction === 'to' ? (item.from || item.addr || '') : (item.to || item.addr || '');
  if (direction === 'to') {
    return [fnName, type, 'incoming', site ? `site ${site}` : ''].filter(Boolean).join(' · ');
  }
  return [fnName, type, 'outgoing', site ? `target ${site}` : ''].filter(Boolean).join(' · ');
}

function renderXrefGroup(title, direction, items, emptyText) {
  if (!items.length) {
    return `
      <div class='panel' style='margin-bottom:10px;'>
        <div class='panel-header'>
          <div class='panel-title'>${escapeHtml(title)}</div>
          <span class='badge'>0</span>
        </div>
        <div class='panel-body'>
          <div class='empty'>${escapeHtml(emptyText)}</div>
        </div>
      </div>
    `;
  }

  return `
    <div class='panel' style='margin-bottom:10px;'>
      <div class='panel-header'>
        <div class='panel-title'>${escapeHtml(title)}</div>
        <span class='badge success'>${items.length}</span>
      </div>
      <div class='panel-body' style='padding:0;'>
        ${items.map((item) => {
          const hitAddr = xrefRowAddress(item, direction);
          const summary = xrefRowSummary(item, direction);
          const encodedAddr = encodeURIComponent(hitAddr || '');
          const canJump = hitAddr && /^0x[0-9a-f]+$/i.test(String(hitAddr));
          return `
            <div class='xref-item' ${canJump ? `data-jump-addr='${encodedAddr}' data-preview-query='${encodedAddr}' data-preview-kind='xref' data-preview-label='${encodeURIComponent(hitAddr || summary)}'` : ''}>
              <div class='row' style='justify-content:space-between;'>
                <span class='mono'>${escapeHtml(hitAddr || '—')}</span>
                <span class='small'>${escapeHtml(item.type || item.kind || direction)}</span>
              </div>
              <div class='small'>${escapeHtml(summary)}</div>
            </div>
          `;
        }).join('')}
      </div>
    </div>
  `;
}

function renderCallGroup(title, items, emptyText) {
  if (!items.length) {
    return `
      <div class='panel' style='margin-bottom:10px;'>
        <div class='panel-header'>
          <div class='panel-title'>${escapeHtml(title)}</div>
          <span class='badge'>0</span>
        </div>
        <div class='panel-body'>
          <div class='empty'>${escapeHtml(emptyText)}</div>
        </div>
      </div>
    `;
  }

  return `
    <div class='panel' style='margin-bottom:10px;'>
      <div class='panel-header'>
        <div class='panel-title'>${escapeHtml(title)}</div>
        <span class='badge success'>${items.length}</span>
      </div>
      <div class='panel-body' style='padding:0;'>
        ${items.map((item) => {
          const encodedAddr = encodeURIComponent(item.addr || '');
          const sites = Array.isArray(item.sites) && item.sites.length ? item.sites.slice(0, 3).join(', ') : '';
          const details = sites ? `callsites: ${sites}` : `${item.count || 1} edge(s)`;
          return `
            <div class='xref-item' data-jump-addr='${encodedAddr}' data-preview-query='${encodedAddr}' data-preview-kind='function' data-preview-label='${encodeURIComponent(item.name || item.addr || "function")}'>
              <div class='row' style='justify-content:space-between;'>
                <span>${escapeHtml(item.name || item.addr || '—')}</span>
                <span class='mono'>${escapeHtml(item.addr || '—')}</span>
              </div>
              <div class='small'>${escapeHtml(details)}</div>
            </div>
          `;
        }).join('')}
      </div>
    </div>
  `;
}

async function loadXrefs(addr) {
  const container = document.getElementById('xrefsList');
  if (!state.selectedSessionId || !addr) {
    container.innerHTML = `<div class='empty'>Select an address with a live session to view cross references.</div>`;
    return;
  }
  try {
    const payload = await api(`/api/sessions/${state.selectedSessionId}/xrefs?addr=${encodeURIComponent(addr)}&limit=50`);
    const grouped = normalizeXrefBuckets(payload.result ?? payload);
    const incoming = grouped.to || [];
    const outgoing = grouped.from || [];
    const refFunctions = grouped.refFunctions || [];
    const callers = grouped.callers || [];
    const callees = grouped.callees || [];
    if (!incoming.length && !outgoing.length && !refFunctions.length && !callers.length && !callees.length) {
      container.innerHTML = `<div class='empty'>No xrefs for ${escapeHtml(addr)}.</div>`;
      return;
    }
    container.innerHTML = `
      ${state.selectedItem?.kind === 'function' ? renderCallGroup('Callers', callers, 'No caller functions found.') : ''}
      ${state.selectedItem?.kind === 'function' ? renderCallGroup('Callees', callees, 'No callee functions found.') : ''}
      ${state.selectedItem?.kind === 'string' ? renderCallGroup('Referencing functions', refFunctions, 'No referencing functions found.') : ''}
      ${renderXrefGroup('Incoming refs (to current)', 'to', incoming, 'No incoming references.')}
      ${renderXrefGroup('Outgoing refs (from current)', 'from', outgoing, 'No outgoing references.')}
    `;
    container.querySelectorAll('[data-jump-addr]').forEach((node) => {
      node.onclick = async () => {
        const jumpAddr = decodeURIComponent(node.getAttribute('data-jump-addr') || '');
        if (!jumpAddr) return;
        document.getElementById('gotoInput').value = jumpAddr;
        await lookupAndOpen();
      };
    });
  } catch (err) {
    container.innerHTML = `<div class='empty'>Xrefs error: ${escapeHtml(err.message)}</div>`;
  }
}

async function refreshInspectorXrefs() {
  await loadXrefs(state.selectedItem?.addr);
}

async function renameSelected() {
  const addr = state.selectedItem?.addr;
  const newName = document.getElementById('renameInput').value.trim();
  if (!state.selectedSessionId || !addr) return setStatus('Select an address with a live session first.', '', true);
  if (!newName) return setStatus('Rename target is required.', '', true);
  await api(`/api/sessions/${state.selectedSessionId}/rename`, {method: 'POST', body: JSON.stringify({addr, new_name: newName})});
  setStatus('Rename applied.', `${addr} → ${newName}`);
  if (state.selectedItem) state.selectedItem.name = newName;
  await refreshIndexes(true);
  await loadSelectionContext();
  renderInspector();
}

async function commentSelected() {
  const addr = state.selectedItem?.addr;
  const comment = document.getElementById('commentInput').value.trim();
  if (!state.selectedSessionId || !addr) return setStatus('Select an address with a live session first.', '', true);
  if (!comment) return setStatus('Comment text is required.', '', true);
  await api(`/api/sessions/${state.selectedSessionId}/comment`, {method: 'POST', body: JSON.stringify({addr, comment})});
  setStatus('Comment saved.', addr);
  await loadSelectionContext();
  await refreshResourcePane();
}

function shouldHandleLiveEvent(payload) {
  return !payload.binary_id || payload.binary_id === state.selectedBinaryId || payload.project_id === state.selectedProjectId || payload.runtime_session_id === state.selectedSessionId;
}

function isStructuralOperation(op) {
  return ['declare_type', 'declare_struct', 'set_type', 'delete_stack', 'declare_stack'].includes(op);
}

function isCodeViewOperation(op) {
  return ['rename', 'set_type', 'set_comments', 'comment', 'patch', 'patch_asm', 'external_mcp_write'].includes(op) || isStructuralOperation(op);
}

function needsFullWorkspaceRefresh(op) {
  return ['open_session', 'close_session', 'refresh_indexes', 'add_binary', 'restore_artifact'].includes(op);
}

function buildLiveStatus(payload) {
  const op = payload.operation_type || payload.event || 'update';
  const target = payload.target ? ` · ${payload.target}` : '';
  return `Live update: ${op}${target}`;
}

function scheduleWorkspaceLiveRefresh(payload) {
  if (!shouldHandleLiveEvent(payload)) return;
  state.lastLiveEvent = payload;
  renderInspector();
  window.clearTimeout(liveRefreshTimer);
  liveRefreshTimer = window.setTimeout(async () => {
    const op = payload.operation_type || payload.event || 'update';

    if (needsFullWorkspaceRefresh(op)) {
      await refreshWorkspace();
    } else {
      await Promise.allSettled([loadIndexState(), refreshResourcePane()]);
      renderInspector();
    }

    if (state.selectedItem?.addr && isCodeViewOperation(op)) {
      await Promise.allSettled([
        loadSelectionContext(),
        loadDecompiler(state.selectedItem.addr),
        loadDisasm(state.selectedItem.addr),
        loadXrefs(state.selectedItem.addr),
      ]);
    }

    if (state.selectedItem?.kind === 'struct' && isStructuralOperation(op)) {
      await refreshResourcePane();
    }

    if (!state.selectedItem && payload.target) {
      document.getElementById('detailsOutput').textContent = prettyJson(payload);
    }

    setStatus(buildLiveStatus(payload));
  }, 250);
}

function connectWorkspaceLiveUpdates() {
  if (!LIVE_WS_URL) return;
  liveSocket = new WebSocket(LIVE_WS_URL);
  liveSocket.onmessage = (event) => {
    try {
      scheduleWorkspaceLiveRefresh(JSON.parse(event.data));
    } catch (_err) {}
  };
  liveSocket.onclose = () => { window.setTimeout(connectWorkspaceLiveUpdates, 1500); };
  liveSocket.onerror = () => liveSocket && liveSocket.close();
}

window.addEventListener('load', async () => {
  try {
    loadLayoutPrefs();
    initSplitters();
    initHoverPreview();
    connectWorkspaceLiveUpdates();
    renderResourceButtons();
    updateNavButtons();
    setTab('decompile');
    renderInspector();
    await refreshWorkspace();
    setStatus('Workspace ready.');
  } catch (err) {
    setStatus(err.message, '', true);
    document.getElementById('detailsOutput').textContent = String(err);
  }
});
