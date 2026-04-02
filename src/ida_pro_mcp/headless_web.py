from __future__ import annotations

import argparse
import atexit
import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from ida_pro_mcp.headless_project_store import HeadlessProjectStore
from ida_pro_mcp.session_mcp_server import SessionMcpServer

logger = logging.getLogger(__name__)

INDEX_HTML = """<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>IDA Workspace</title>
<style>
:root {
  --bg: #1e1e1e;
  --panel: #252526;
  --panel-2: #2d2d30;
  --border: #3c3c3c;
  --text: #d4d4d4;
  --muted: #9da5b4;
  --accent: #0e639c;
  --accent-2: #3794ff;
  --danger: #c74e39;
  --success: #2ea043;
  --selection: #37373d;
  --shadow: rgba(0, 0, 0, 0.28);
  --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', monospace;
}
* { box-sizing: border-box; }
html, body { height: 100%; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font: 13px/1.4 -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
}
button, input, textarea {
  font: inherit;
}
button {
  border: 1px solid var(--border);
  background: var(--panel-2);
  color: var(--text);
  border-radius: 6px;
  padding: 7px 10px;
  cursor: pointer;
}
button:hover { border-color: #5a5a5a; }
button.primary { background: var(--accent); border-color: #1177bb; }
button.primary:hover { background: #1177bb; }
button.ghost { background: transparent; }
button.active { background: var(--accent); border-color: var(--accent-2); }
button:disabled { opacity: 0.45; cursor: not-allowed; }
input, textarea {
  width: 100%;
  border: 1px solid var(--border);
  background: #1f1f1f;
  color: var(--text);
  border-radius: 6px;
  padding: 8px 10px;
}
textarea { min-height: 88px; resize: vertical; }
pre {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
  font-family: var(--mono);
  font-size: 12px;
}
code, .mono { font-family: var(--mono); }
.small { font-size: 12px; color: var(--muted); }
.app {
  height: 100vh;
  display: grid;
  grid-template-rows: 44px 56px 1fr 24px;
}
.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 14px;
  border-bottom: 1px solid var(--border);
  background: #181818;
}
.brand {
  display: flex;
  align-items: center;
  gap: 10px;
  font-weight: 600;
}
.brand small { color: var(--muted); font-weight: 500; }
.pill {
  border: 1px solid var(--border);
  border-radius: 999px;
  padding: 4px 10px;
  background: var(--panel);
  color: var(--muted);
}
.commandbar {
  display: grid;
  grid-template-columns: minmax(220px, 0.8fr) minmax(360px, 1.4fr) minmax(360px, 1fr);
  gap: 12px;
  padding: 10px 14px;
  border-bottom: 1px solid var(--border);
  background: #202020;
}
.group {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}
.layout {
  min-height: 0;
  display: grid;
  grid-template-columns: 320px minmax(400px, 1fr) 330px;
}
.sidebar, .inspector, .editor {
  min-height: 0;
}
.sidebar, .inspector {
  background: var(--panel);
}
.sidebar { border-right: 1px solid var(--border); }
.inspector { border-left: 1px solid var(--border); }
.column {
  height: 100%;
  overflow: auto;
  padding: 12px;
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.panel {
  border: 1px solid var(--border);
  background: #202124;
  border-radius: 8px;
  box-shadow: 0 10px 24px -16px var(--shadow);
  overflow: hidden;
}
.panel-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 10px 12px;
  border-bottom: 1px solid var(--border);
  background: #26272b;
}
.panel-title { font-size: 12px; letter-spacing: 0.04em; text-transform: uppercase; color: var(--muted); }
.panel-body { padding: 10px 12px; }
.panel.fill { flex: 1; min-height: 0; }
.meta-grid {
  display: grid;
  grid-template-columns: 78px 1fr;
  gap: 8px 10px;
  align-items: start;
}
.meta-grid .label { color: var(--muted); }
.meta-grid .value { word-break: break-word; }
.tree, .list {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.tree-project, .tree-binary, .list-item, .history-item, .xref-item, .table-row {
  border: 1px solid transparent;
  border-radius: 6px;
  padding: 8px 10px;
}
.tree-project, .tree-binary, .list-item, .table-row, .xref-item { cursor: pointer; }
.tree-project:hover, .tree-binary:hover, .list-item:hover, .table-row:hover, .xref-item:hover { background: #2b2d31; }
.tree-project.active, .tree-binary.active, .list-item.active, .table-row.active, .xref-item.active { background: var(--selection); border-color: #52525b; }
.tree-binaries { margin: 6px 0 0 14px; display: flex; flex-direction: column; gap: 6px; }
.row { display: flex; align-items: center; gap: 8px; }
.row.wrap { flex-wrap: wrap; }
.badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  border-radius: 999px;
  padding: 2px 8px;
  font-size: 11px;
  background: #1a1a1a;
  color: var(--muted);
  border: 1px solid var(--border);
}
.badge.success { color: #9be9a8; border-color: rgba(46,160,67,.55); }
.badge.warn { color: #f2cc60; }
.segmented { display: flex; gap: 6px; flex-wrap: wrap; }
.segmented button { flex: 1; min-width: 0; }
.editor {
  min-width: 0;
  background: #1f1f1f;
  display: grid;
  grid-template-rows: 42px 1fr;
}
.tabs {
  display: flex;
  align-items: center;
  gap: 2px;
  padding: 6px 10px;
  border-bottom: 1px solid var(--border);
  background: #252526;
}
.tab {
  background: transparent;
  border: 1px solid transparent;
  border-bottom: none;
  border-radius: 6px 6px 0 0;
  padding: 8px 12px;
  color: var(--muted);
}
.tab.active {
  background: #1e1e1e;
  color: var(--text);
  border-color: var(--border);
}
.views { min-height: 0; position: relative; }
.view {
  display: none;
  position: absolute;
  inset: 0;
  overflow: auto;
  padding: 14px;
}
.view.active { display: block; }
.code-view {
  border: 1px solid var(--border);
  background: #1a1a1a;
  border-radius: 8px;
  padding: 14px;
  min-height: 100%;
}
.table {
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: hidden;
}
.table-header, .table-row {
  display: grid;
  grid-template-columns: 140px 1fr;
  gap: 12px;
  align-items: start;
}
.table-header {
  padding: 10px 12px;
  background: #252526;
  border-bottom: 1px solid var(--border);
  color: var(--muted);
  text-transform: uppercase;
  font-size: 11px;
  letter-spacing: .05em;
}
.table-row { border-top: 1px solid #2b2b2b; }
.empty {
  border: 1px dashed var(--border);
  border-radius: 8px;
  padding: 18px;
  color: var(--muted);
  background: rgba(255,255,255,0.015);
}
.statusbar {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 0 12px;
  border-top: 1px solid var(--border);
  background: #007acc;
  color: white;
  font-size: 12px;
}
.statusbar .muted { opacity: 0.9; }
.linkish { color: #4fc1ff; cursor: pointer; }
@media (max-width: 1280px) {
  .commandbar { grid-template-columns: 1fr; }
  .layout { grid-template-columns: 280px 1fr; }
  .inspector { display: none; }
}
</style>
</head>
<body>
<div class='app'>
  <header class='topbar'>
    <div class='brand'>
      <span>IDA Workspace</span>
      <small>headless · upstream ida tools</small>
    </div>
    <div id='selectionPill' class='pill'>No binary selected</div>
  </header>

  <div class='commandbar'>
    <div class='group'>
      <input id='projectName' placeholder='New project name'>
      <button class='primary' onclick='createProject()'>Create Project</button>
    </div>
    <div class='group'>
      <input id='artifactPath' placeholder='/path/to/binary or .i64'>
      <button onclick='addBinary()'>Add Binary</button>
      <button onclick='restoreArtifact()'>Restore</button>
    </div>
    <div class='group'>
      <button id='startSessionBtn' onclick='openSession()'>Start Session</button>
      <button id='refreshIndexesBtn' onclick='refreshIndexes()'>Refresh Indexes</button>
      <input id='gotoInput' placeholder='Address or symbol'>
      <button onclick='lookupAndOpen()'>Go</button>
    </div>
  </div>

  <div class='layout'>
    <aside class='sidebar'>
      <div class='column'>
        <section class='panel'>
          <div class='panel-header'>
            <div class='panel-title'>Workspace</div>
            <span id='sessionBadge' class='badge warn'>No live session</span>
          </div>
          <div class='panel-body'>
            <div id='workspaceMeta' class='meta-grid'></div>
          </div>
        </section>

        <section class='panel'>
          <div class='panel-header'>
            <div class='panel-title'>Projects</div>
            <button class='ghost' onclick='refreshWorkspace()'>Refresh</button>
          </div>
          <div class='panel-body'>
            <div id='projectTree' class='tree'></div>
          </div>
        </section>

        <section class='panel fill'>
          <div class='panel-header'>
            <div class='panel-title'>Explorer</div>
            <div id='indexBadges' class='row wrap'></div>
          </div>
          <div class='panel-body' style='display:flex;flex-direction:column;gap:10px;min-height:0;height:100%;'>
            <div class='segmented'>
              <button id='resource-functions' onclick="setResourceMode('functions')">Functions</button>
              <button id='resource-strings' onclick="setResourceMode('strings')">Strings</button>
              <button id='resource-structs' onclick="setResourceMode('structs')">Structs</button>
              <button id='resource-history' onclick="setResourceMode('history')">History</button>
            </div>
            <input id='resourceFilter' placeholder='Filter current explorer' oninput='onResourceFilterChange()'>
            <div id='resourceList' class='list' style='overflow:auto;min-height:260px;'></div>
          </div>
        </section>
      </div>
    </aside>

    <main class='editor'>
      <div class='tabs'>
        <button id='tab-decompile' class='tab' onclick="setTab('decompile')">Decompiler</button>
        <button id='tab-disasm' class='tab' onclick="setTab('disasm')">Disassembly</button>
        <button id='tab-strings' class='tab' onclick="setTab('strings')">Strings</button>
        <button id='tab-structs' class='tab' onclick="setTab('structs')">Structs</button>
        <button id='tab-history' class='tab' onclick="setTab('history')">History</button>
      </div>
      <div class='views'>
        <section id='view-decompile' class='view'>
          <div class='code-view'><pre id='decompileOutput'>Select a function or use Go to load pseudocode.</pre></div>
        </section>
        <section id='view-disasm' class='view'>
          <div class='code-view'><pre id='disasmOutput'>Select a function or use Go to load disassembly.</pre></div>
        </section>
        <section id='view-strings' class='view'>
          <div id='stringsTable'></div>
        </section>
        <section id='view-structs' class='view'>
          <div id='structsTable'></div>
        </section>
        <section id='view-history' class='view'>
          <div id='historyTable'></div>
        </section>
      </div>
    </main>

    <aside class='inspector'>
      <div class='column'>
        <section class='panel'>
          <div class='panel-header'><div class='panel-title'>Inspector</div></div>
          <div class='panel-body'>
            <div id='inspectorSummary' class='meta-grid'></div>
          </div>
        </section>

        <section class='panel'>
          <div class='panel-header'>
            <div class='panel-title'>Xrefs</div>
            <button class='ghost' onclick='refreshInspectorXrefs()'>Refresh</button>
          </div>
          <div class='panel-body'>
            <div id='xrefsList' class='list'></div>
          </div>
        </section>

        <section class='panel'>
          <div class='panel-header'><div class='panel-title'>Actions</div></div>
          <div class='panel-body' style='display:flex;flex-direction:column;gap:10px;'>
            <div>
              <div class='small' style='margin-bottom:4px;'>Rename selected address</div>
              <div class='row'>
                <input id='renameInput' placeholder='new_symbol_name'>
                <button onclick='renameSelected()'>Save</button>
              </div>
            </div>
            <div>
              <div class='small' style='margin-bottom:4px;'>Comment selected address</div>
              <textarea id='commentInput' placeholder='Comment text'></textarea>
              <div class='row' style='margin-top:8px;'>
                <button onclick='commentSelected()'>Save Comment</button>
              </div>
            </div>
          </div>
        </section>

        <section class='panel fill'>
          <div class='panel-header'><div class='panel-title'>Details</div></div>
          <div class='panel-body' style='min-height:280px;'>
            <pre id='detailsOutput'>No selection.</pre>
          </div>
        </section>
      </div>
    </aside>
  </div>

  <footer class='statusbar'>
    <span id='statusText'>Ready.</span>
    <span id='statusMeta' class='muted'></span>
  </footer>
</div>

<script>
const state = {
  projects: [],
  sessions: [],
  selectedProjectId: null,
  selectedBinaryId: null,
  selectedSessionId: null,
  resourceMode: 'functions',
  activeTab: 'decompile',
  selectedItem: null,
  currentIndexState: null,
  currentResourceItems: [],
  loading: false,
};

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function setStatus(message, meta = '', isError = false) {
  const text = document.getElementById('statusText');
  const metaEl = document.getElementById('statusMeta');
  text.textContent = message;
  metaEl.textContent = meta || '';
  document.querySelector('.statusbar').style.background = isError ? '#a1260d' : '#007acc';
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
  const rows = [
    ['Project', project ? project.name : '—'],
    ['Binary', binary ? binary.display_name : '—'],
    ['Path', binary ? binary.binary_path : '—'],
    ['IDB', binary?.idb_path || '—'],
    ['Session', state.selectedSessionId || '—'],
  ];
  document.getElementById('workspaceMeta').innerHTML = rows.map(([label, value]) => `
    <div class='label'>${escapeHtml(label)}</div>
    <div class='value mono'>${escapeHtml(value)}</div>
  `).join('');
  document.getElementById('selectionPill').textContent = binary
    ? `${binary.display_name}${state.selectedSessionId ? ' · live' : ' · no session'}`
    : 'No binary selected';
  const badge = document.getElementById('sessionBadge');
  if (session && session.live) {
    badge.textContent = 'Live session';
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
      const binaryEl = document.createElement('div');
      binaryEl.className = `tree-binary${isActive ? ' active' : ''}`;
      binaryEl.innerHTML = `
        <div class='row' style='justify-content:space-between;'>
          <span>${escapeHtml(binary.display_name)}</span>
          <span class='badge ${hasLive ? 'success' : ''}'>${hasLive ? 'live' : 'idle'}</span>
        </div>
        <div class='small mono'>${escapeHtml(binary.idb_path || binary.binary_path)}</div>
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

function renderInspector() {
  const binary = selectedBinary();
  const item = state.selectedItem;
  const rows = [
    ['Kind', item?.kind || '—'],
    ['Name', item?.name || '—'],
    ['Address', item?.addr || '—'],
    ['Binary', binary?.display_name || '—'],
    ['Session', state.selectedSessionId || '—'],
  ];
  document.getElementById('inspectorSummary').innerHTML = rows.map(([label, value]) => `
    <div class='label'>${escapeHtml(label)}</div>
    <div class='value mono'>${escapeHtml(value)}</div>
  `).join('');
  document.getElementById('renameInput').value = item?.name && !String(item.name).startsWith('0x') ? item.name : '';
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

  if (state.selectedProjectId && !findProject(state.selectedProjectId)) {
    state.selectedProjectId = null;
  }
  if (!state.selectedProjectId && state.projects.length) {
    state.selectedProjectId = state.projects[0].project_id;
  }

  if (state.selectedBinaryId && !findBinary(state.selectedBinaryId)) {
    state.selectedBinaryId = null;
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
  setStatus('Session started.', payload.session.runtime_session_id);
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
    if (current.every((item) => typeof item === 'string')) return current.join('\\n');
    return current.map((item) => {
      if (typeof item === 'string') return item;
      if (item.line) return item.line;
      if (item.text) return item.text;
      if (item.disasm) return item.disasm;
      if (item.address || item.addr) return `${item.address || item.addr} ${item.text || item.disasm || ''}`.trim();
      return prettyJson(item);
    }).join('\\n');
  }
  if (typeof current === 'object') {
    if (typeof current.code === 'string') return current.code;
    if (Array.isArray(current.pseudocode)) return current.pseudocode.join('\\n');
    if (typeof current.pseudocode === 'string') return current.pseudocode;
    if (Array.isArray(current.lines)) {
      return current.lines.map((line) => typeof line === 'string' ? line : (line.line || line.text || prettyJson(line))).join('\\n');
    }
    if (current.asm && Array.isArray(current.asm.lines)) {
      return current.asm.lines
        .map((line) => `${line.addr || ''} ${line.instruction || line.text || ''}`.trim())
        .join('\\n');
    }
    if (Array.isArray(current.instructions)) {
      return current.instructions.map((insn) => {
        const addr = insn.address || insn.addr || insn.ea || '';
        const text = insn.text || insn.disasm || [insn.mnemonic, insn.operands].filter(Boolean).join(' ');
        return `${addr} ${text}`.trim();
      }).join('\\n');
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

async function selectFunction(item) {
  state.selectedItem = {
    kind: 'function',
    name: item.name || item.addr || 'function',
    addr: item.addr || '',
    raw: item,
  };
  document.getElementById('gotoInput').value = item.addr || item.name || '';
  renderInspector();
  document.getElementById('detailsOutput').textContent = prettyJson(item);
  await refreshResourcePane();
  setTab('decompile');
  await loadLookupDetails(item.addr || item.name || '');
  await Promise.all([loadDecompiler(item.addr), loadDisasm(item.addr), loadXrefs(item.addr)]);
}

async function selectString(item) {
  state.selectedItem = {
    kind: 'string',
    name: item.string || item.addr || 'string',
    addr: item.addr || '',
    raw: item,
  };
  document.getElementById('gotoInput').value = item.addr || '';
  renderInspector();
  document.getElementById('detailsOutput').textContent = prettyJson(item);
  await refreshResourcePane();
  setTab('strings');
  await loadXrefs(item.addr);
}

async function selectStruct(item) {
  state.selectedItem = {
    kind: 'struct',
    name: item.name || 'struct',
    addr: item.addr || '',
    raw: item,
  };
  renderInspector();
  document.getElementById('detailsOutput').textContent = prettyJson(item);
  await refreshResourcePane();
  setTab('structs');
  document.getElementById('xrefsList').innerHTML = `<div class='empty'>Cross references are address-based; select a function or string to inspect xrefs.</div>`;
}

function selectHistoryEntry(item) {
  state.selectedItem = {
    kind: 'history',
    name: item.operation_type || 'history',
    addr: item.target || '',
    raw: item,
  };
  renderInspector();
  document.getElementById('detailsOutput').textContent = prettyJson(item);
  refreshResourcePane();
  setTab('history');
}

async function lookupAndOpen() {
  const query = document.getElementById('gotoInput').value.trim();
  if (!query) return setStatus('Enter an address or symbol.', '', true);
  if (!state.selectedSessionId) return setStatus('Start a session first.', '', true);
  const payload = await api(`/api/sessions/${state.selectedSessionId}/lookup?query=${encodeURIComponent(query)}`);
  const normalized = unwrapResult(payload.result ?? payload);
  const addr = findFirstAddress(normalized) || query;
  state.selectedItem = {
    kind: 'lookup',
    name: query,
    addr,
    raw: normalized,
  };
  renderInspector();
  document.getElementById('detailsOutput').textContent = prettyJson(normalized);
  setStatus('Resolved symbol/address.', addr);
  if (/^0x[0-9a-f]+$/i.test(addr)) {
    await Promise.all([loadDecompiler(addr), loadDisasm(addr), loadXrefs(addr)]);
    setTab('decompile');
  }
}

async function loadLookupDetails(query) {
  if (!state.selectedSessionId || !query) return;
  try {
    const payload = await api(`/api/sessions/${state.selectedSessionId}/lookup?query=${encodeURIComponent(query)}`);
    const normalized = unwrapResult(payload.result ?? payload);
    if (state.selectedItem) state.selectedItem.raw = normalized;
    document.getElementById('detailsOutput').textContent = prettyJson(normalized);
    renderInspector();
  } catch (err) {
    document.getElementById('detailsOutput').textContent = `Lookup failed: ${err.message}`;
  }
}

async function loadDecompiler(addr) {
  if (!state.selectedSessionId || !addr) {
    document.getElementById('decompileOutput').textContent = 'Start a session and select a function to view pseudocode.';
    return;
  }
  try {
    const payload = await api(`/api/sessions/${state.selectedSessionId}/decompile?addr=${encodeURIComponent(addr)}`);
    document.getElementById('decompileOutput').textContent = extractTextBlock(payload.result ?? payload);
  } catch (err) {
    document.getElementById('decompileOutput').textContent = `Decompiler error: ${err.message}`;
  }
}

async function loadDisasm(addr) {
  if (!state.selectedSessionId || !addr) {
    document.getElementById('disasmOutput').textContent = 'Start a session and select a function to view disassembly.';
    return;
  }
  try {
    const payload = await api(`/api/sessions/${state.selectedSessionId}/disasm?addr=${encodeURIComponent(addr)}`);
    document.getElementById('disasmOutput').textContent = extractTextBlock(payload.result ?? payload);
  } catch (err) {
    document.getElementById('disasmOutput').textContent = `Disassembly error: ${err.message}`;
  }
}

function flattenXrefs(value) {
  const current = unwrapResult(value);
  if (Array.isArray(current)) {
    return current.flatMap((item) => flattenXrefs(item));
  }
  if (current && typeof current === 'object') {
    if (Array.isArray(current.xrefs)) return current.xrefs;
    if (Array.isArray(current.refs)) return current.refs;
    return [current];
  }
  return [];
}

async function loadXrefs(addr) {
  const container = document.getElementById('xrefsList');
  if (!state.selectedSessionId || !addr) {
    container.innerHTML = `<div class='empty'>Select an address with a live session to view cross references.</div>`;
    return;
  }
  try {
    const payload = await api(`/api/sessions/${state.selectedSessionId}/xrefs?addr=${encodeURIComponent(addr)}&limit=50`);
    const items = flattenXrefs(payload.result ?? payload);
    if (!items.length) {
      container.innerHTML = `<div class='empty'>No xrefs for ${escapeHtml(addr)}.</div>`;
      return;
    }
    container.innerHTML = '';
    items.forEach((item) => {
      const hitAddr = item.frm || item.from || item.addr || item.address || item.ea || findFirstAddress(item);
      const summary = item.type || item.kind || item.name || item.text || 'xref';
      const el = document.createElement('div');
      el.className = 'xref-item';
      el.innerHTML = `<div class='row' style='justify-content:space-between;'><span class='mono'>${escapeHtml(hitAddr || '—')}</span><span class='small'>${escapeHtml(summary)}</span></div><div class='small'>${escapeHtml(prettyJson(item).slice(0, 160))}</div>`;
      if (hitAddr && /^0x[0-9a-f]+$/i.test(String(hitAddr))) {
        el.onclick = async () => {
          document.getElementById('gotoInput').value = hitAddr;
          await lookupAndOpen();
        };
      }
      container.appendChild(el);
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
  renderInspector();
}

async function commentSelected() {
  const addr = state.selectedItem?.addr;
  const comment = document.getElementById('commentInput').value.trim();
  if (!state.selectedSessionId || !addr) return setStatus('Select an address with a live session first.', '', true);
  if (!comment) return setStatus('Comment text is required.', '', true);
  await api(`/api/sessions/${state.selectedSessionId}/comment`, {method: 'POST', body: JSON.stringify({addr, comment})});
  setStatus('Comment saved.', addr);
  await refreshResourcePane();
}

window.addEventListener('load', async () => {
  try {
    renderResourceButtons();
    setTab('decompile');
    renderInspector();
    await refreshWorkspace();
    setStatus('Workspace ready.');
  } catch (err) {
    setStatus(err.message, '', true);
    document.getElementById('detailsOutput').textContent = String(err);
  }
});
</script>
</body>
</html>
"""


class HeadlessWebBackend:
    def __init__(self, db_path: Path, unsafe: bool = False, verbose: bool = False):
        self.store = HeadlessProjectStore(db_path)
        self.sessions = SessionMcpServer(unsafe=unsafe, verbose=verbose)

    def shutdown(self) -> None:
        self.sessions.cleanup()

    def ensure_project(self, name: str, root_dir: str | Path | None = None) -> dict[str, Any]:
        normalized = name.strip()
        if not normalized:
            raise ValueError('project name is required')
        for project in self.store.list_projects():
            if project['name'] == normalized:
                return self.store.get_project(project['project_id']) or project
        return self.store.create_project(normalized, root_dir or str(Path.cwd()))

    def bootstrap_artifacts(
        self,
        project_name: str,
        artifact_paths: list[str],
        *,
        root_dir: str | Path | None = None,
        open_session: bool = False,
        refresh_indexes: bool = False,
    ) -> dict[str, Any]:
        project = self.ensure_project(project_name, root_dir)
        bootstrapped: list[dict[str, Any]] = []
        for artifact_path in artifact_paths:
            restored = self.restore_artifact(project['project_id'], {'artifact_path': artifact_path})
            binary = restored['binary']
            item: dict[str, Any] = {'binary': binary, 'restored': True}
            if open_session:
                opened = self.open_session(binary['binary_id'])
                item['session'] = opened['session']
                if refresh_indexes:
                    item['indexes'] = self.refresh_indexes(binary['binary_id'], opened['session']['runtime_session_id'])
            bootstrapped.append(item)
        return {'project': project, 'items': bootstrapped}

    def list_projects(self) -> dict[str, Any]:
        projects = self.store.list_projects()
        for project in projects:
            project['binaries'] = self.store.list_binaries(project['project_id'])
        return {'projects': projects}

    def _require_binary(self, binary_id: str) -> dict[str, Any]:
        binary = self.store.get_binary(binary_id)
        if binary is None:
            raise KeyError(f'binary not found: {binary_id}')
        return binary

    def _require_live_session_for_binary(self, binary_id: str) -> dict[str, Any]:
        session = self.store.get_live_session_for_binary(binary_id)
        if session is None:
            raise RuntimeError(
                f'no live session for binary {binary_id}; start a session first'
            )
        return session

    def _session_context(self, runtime_session_id: str) -> dict[str, Any]:
        session = self.store.get_session(runtime_session_id)
        if session is None:
            raise KeyError(f'session not found: {runtime_session_id}')
        return session

    def _record_operation(
        self,
        operation_type: str,
        *,
        payload: dict[str, Any] | list[Any] | None,
        result: dict[str, Any] | list[Any] | None,
        project_id: str | None = None,
        binary_id: str | None = None,
        runtime_session_id: str | None = None,
        target: str | None = None,
    ) -> None:
        self.store.record_operation(
            operation_type,
            payload,
            result,
            project_id=project_id,
            binary_id=binary_id,
            runtime_session_id=runtime_session_id,
            target=target,
        )

    @staticmethod
    def _unwrap_tool_result(value: Any) -> Any:
        if isinstance(value, dict) and "result" in value and len(value) == 1:
            return value["result"]
        return value

    def create_project(self, payload: dict[str, Any]) -> dict[str, Any]:
        name = (payload.get('name') or '').strip()
        if not name:
            raise ValueError('name is required')
        root_dir = payload.get('root_dir') or str(Path.cwd())
        return {'project': self.store.create_project(name, root_dir)}

    def add_binary(self, project_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        binary_path = payload.get('binary_path')
        if not binary_path:
            raise ValueError('binary_path is required')
        return {'binary': self.store.add_binary(project_id, binary_path, payload.get('display_name'))}

    def restore_artifact(self, project_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        artifact_path = payload.get('artifact_path') or payload.get('binary_path')
        if not artifact_path:
            raise ValueError('artifact_path is required')
        binary = self.store.add_binary(project_id, artifact_path, payload.get('display_name'))
        result = {'binary': binary, 'restored': True}
        self._record_operation(
            'restore_artifact',
            payload=payload,
            result=result,
            project_id=project_id,
            binary_id=binary['binary_id'],
            target=str(artifact_path),
        )
        return result

    def open_session(self, binary_id: str) -> dict[str, Any]:
        binary = self._require_binary(binary_id)
        open_path = binary.get('idb_path') or binary['binary_path']
        if binary.get('idb_path') and not Path(str(binary['idb_path'])).exists():
            open_path = binary['binary_path']
        session = self.sessions.create_session(str(open_path))
        self.store.record_session_open(
            project_id=binary['project_id'],
            binary_id=binary_id,
            runtime_session_id=session['session_id'],
            worker_port=session.get('port'),
            worker_pid=session.get('pid'),
            status=session.get('status', 'ready'),
            metadata={'binary_path': binary['binary_path'], 'open_path': str(open_path)},
        )
        idb_path = Path(binary['binary_path'])
        if idb_path.suffix.lower() not in {'.i64', '.idb'}:
            idb_path = idb_path.with_suffix('.i64')
        self.store.update_binary_idb_path(binary_id, idb_path)
        result = {'session': self.store.get_session(session['session_id']), 'live': session}
        self._record_operation(
            'open_session',
            payload={'binary_id': binary_id, 'open_path': str(open_path)},
            result=result,
            project_id=binary['project_id'],
            binary_id=binary_id,
            runtime_session_id=session['session_id'],
            target=str(open_path),
        )
        return result

    def close_session(self, runtime_session_id: str) -> dict[str, Any]:
        session = self.store.get_session(runtime_session_id)
        ok = self.sessions.close_session(runtime_session_id)
        if ok:
            self.store.record_session_close(runtime_session_id)
        result = {'ok': ok, 'session_id': runtime_session_id}
        if session is not None:
            self._record_operation(
                'close_session',
                payload={'runtime_session_id': runtime_session_id},
                result=result,
                project_id=session['project_id'],
                binary_id=session['binary_id'],
                runtime_session_id=runtime_session_id,
                target=runtime_session_id,
            )
        return result

    def list_sessions(self) -> dict[str, Any]:
        live_map = {s['session_id']: s for s in self.sessions.list_session_records()}
        items = self.store.list_sessions(include_closed=False)
        for item in items:
            item['live'] = live_map.get(item['runtime_session_id'])
        return {'sessions': items}

    def session_tool(self, runtime_session_id: str, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        result = self.sessions.call_tool(tool_name, arguments, session_id=runtime_session_id)
        return {'session_id': runtime_session_id, 'tool': tool_name, 'result': result}

    def list_history(self, binary_id: str, limit: int = 100) -> dict[str, Any]:
        binary = self._require_binary(binary_id)
        return {
            'binary_id': binary_id,
            'operations': self.store.list_operations(binary_id=binary_id, limit=limit),
            'binary': binary,
        }

    def list_strings(self, runtime_session_id: str, query: str, offset: int = 0, limit: int = 100) -> dict[str, Any]:
        return self.session_tool(runtime_session_id, 'find_regex', {'pattern': query or '.', 'offset': offset, 'limit': limit})

    def lookup(self, runtime_session_id: str, query: str) -> dict[str, Any]:
        if not query:
            raise ValueError('query is required')
        return self.session_tool(runtime_session_id, 'lookup_funcs', {'queries': query})

    def xrefs(self, runtime_session_id: str, addr: str, limit: int = 50) -> dict[str, Any]:
        if not addr:
            raise ValueError('addr is required')
        return self.session_tool(runtime_session_id, 'xrefs_to', {'addrs': addr, 'limit': limit})

    def decompile(self, runtime_session_id: str, addr: str) -> dict[str, Any]:
        if not addr:
            raise ValueError('addr is required')
        return self.session_tool(runtime_session_id, 'decompile', {'addr': addr})

    def disasm(self, runtime_session_id: str, addr: str) -> dict[str, Any]:
        if not addr:
            raise ValueError('addr is required')
        return self.session_tool(runtime_session_id, 'disasm', {'addr': addr})

    def list_structs(self, runtime_session_id: str, struct_filter: str) -> dict[str, Any]:
        return self.session_tool(runtime_session_id, 'search_structs', {'filter': struct_filter or ''})

    def patch_bytes(self, runtime_session_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        addr = payload.get('addr')
        data = payload.get('data')
        if not addr or not data:
            raise ValueError('addr and data are required')
        result = self.session_tool(runtime_session_id, 'patch', {'patches': {'addr': addr, 'data': data}})
        ctx = self._session_context(runtime_session_id)
        self._record_operation(
            'patch_bytes',
            payload=payload,
            result=result,
            project_id=ctx['project_id'],
            binary_id=ctx['binary_id'],
            runtime_session_id=runtime_session_id,
            target=str(addr),
        )
        return result

    def patch_asm(self, runtime_session_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        addr = payload.get('addr')
        asm = payload.get('asm')
        if not addr or not asm:
            raise ValueError('addr and asm are required')
        result = self.session_tool(runtime_session_id, 'patch_asm', {'items': {'addr': addr, 'asm': asm}})
        ctx = self._session_context(runtime_session_id)
        self._record_operation(
            'patch_asm',
            payload=payload,
            result=result,
            project_id=ctx['project_id'],
            binary_id=ctx['binary_id'],
            runtime_session_id=runtime_session_id,
            target=str(addr),
        )
        return result

    def apply_type(self, runtime_session_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        addr = payload.get('addr')
        type_decl = payload.get('type_decl')
        kind = (payload.get('kind') or '').strip()
        name = (payload.get('name') or '').strip()
        if not addr or not type_decl:
            raise ValueError('addr and type_decl are required')

        edit: dict[str, Any] = {'addr': addr}
        if kind:
            edit['kind'] = kind
        if kind == 'function':
            edit['signature'] = type_decl
        else:
            edit['ty'] = type_decl
        if kind == 'global' and name:
            edit['name'] = name
        elif kind == 'local' and name:
            edit['variable'] = name
        elif kind == 'stack' and name:
            edit['name'] = name

        result = self.session_tool(runtime_session_id, 'set_type', {'edits': edit})
        ctx = self._session_context(runtime_session_id)
        self._record_operation(
            'set_type',
            payload=edit,
            result=result,
            project_id=ctx['project_id'],
            binary_id=ctx['binary_id'],
            runtime_session_id=runtime_session_id,
            target=str(addr),
        )
        return result

    def read_struct(self, runtime_session_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        addr = payload.get('addr')
        struct_name = (payload.get('struct_name') or '').strip()
        if not addr:
            raise ValueError('addr is required')
        query: dict[str, Any] = {'addr': addr}
        if struct_name:
            query['struct'] = struct_name
        result = self.session_tool(runtime_session_id, 'read_struct', {'queries': query})
        ctx = self._session_context(runtime_session_id)
        self._record_operation(
            'read_struct',
            payload=query,
            result=result,
            project_id=ctx['project_id'],
            binary_id=ctx['binary_id'],
            runtime_session_id=runtime_session_id,
            target=str(addr),
        )
        return result

    def declare_struct(self, runtime_session_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        struct_name = (payload.get('struct_name') or '').strip()
        body = (payload.get('body') or '').strip()
        if not struct_name or not body:
            raise ValueError('struct_name and body are required')

        decls = payload.get('decls')
        if not decls:
            decls = f"struct {struct_name} {{\n{body}\n}};"

        result = self.session_tool(runtime_session_id, 'declare_type', {'decls': decls})
        ctx = self._session_context(runtime_session_id)
        structs = self.sessions.call_tool(
            'search_structs',
            {'filter': struct_name},
            session_id=runtime_session_id,
        )
        structs = self._unwrap_tool_result(structs)
        if isinstance(structs, list):
            current = self.store.list_struct_index(ctx['binary_id'], '', 100000, 0)
            merged = {item.get('name'): item for item in current}
            for item in structs:
                if item.get('name'):
                    merged[item['name']] = item
            self.store.replace_struct_index(ctx['binary_id'], list(merged.values()))

        wrapped = {'decls': decls, 'result': result}
        self._record_operation(
            'declare_struct',
            payload={'struct_name': struct_name, 'decls': decls},
            result=wrapped,
            project_id=ctx['project_id'],
            binary_id=ctx['binary_id'],
            runtime_session_id=runtime_session_id,
            target=struct_name,
        )
        return wrapped

    def refresh_indexes(self, binary_id: str, runtime_session_id: str | None = None) -> dict[str, Any]:
        binary = self._require_binary(binary_id)
        session = (
            self.store.get_session(runtime_session_id)
            if runtime_session_id
            else self.store.get_live_session_for_binary(binary_id)
        )
        if session is None:
            opened = self.open_session(binary_id)
            session = opened['session']

        sid = session['runtime_session_id']

        functions: list[dict[str, Any]] = []
        offset = 0
        while True:
            page_result = self.sessions.call_tool(
                'list_funcs',
                {'queries': {'filter': '*', 'offset': offset, 'count': 500}},
                session_id=sid,
            )
            page_result = self._unwrap_tool_result(page_result)
            page = page_result[0] if isinstance(page_result, list) else page_result
            batch = page.get('data', [])
            functions.extend(batch)
            if page.get('next_offset') is None:
                break
            offset = int(page['next_offset'])
        self.store.replace_function_index(binary_id, functions)

        strings: list[dict[str, Any]] = []
        offset = 0
        while True:
            string_result = self.sessions.call_tool(
                'find_regex',
                {'pattern': '.*', 'offset': offset, 'limit': 500},
                session_id=sid,
            )
            string_result = self._unwrap_tool_result(string_result)
            batch = string_result.get('matches', [])
            strings.extend(batch)
            cursor = string_result.get('cursor', {})
            if 'next' not in cursor:
                break
            offset = int(cursor['next'])
        self.store.replace_string_index(binary_id, strings)

        structs = self.sessions.call_tool(
            'search_structs',
            {'filter': ''},
            session_id=sid,
        )
        structs = self._unwrap_tool_result(structs)
        self.store.replace_struct_index(binary_id, structs if isinstance(structs, list) else [])

        self.store.update_binary_idb_path(
            binary_id,
            binary.get('idb_path') or Path(binary['binary_path']).with_suffix('.i64'),
        )

        result = {
            'binary_id': binary_id,
            'session_id': sid,
            'counts': {
                'functions': len(functions),
                'strings': len(strings),
                'structs': len(structs) if isinstance(structs, list) else 0,
            },
            'index_state': self.store.get_binary_index_state(binary_id),
        }
        self._record_operation(
            'refresh_indexes',
            payload={'binary_id': binary_id},
            result=result,
            project_id=binary['project_id'],
            binary_id=binary_id,
            runtime_session_id=sid,
            target=binary.get('display_name') or binary['binary_path'],
        )
        return result

    def get_binary_indexes(self, binary_id: str) -> dict[str, Any]:
        binary = self._require_binary(binary_id)
        return {
            'binary': binary,
            'index_state': self.store.get_binary_index_state(binary_id),
        }

    def cached_functions(
        self, binary_id: str, filter_text: str = '', limit: int = 200, offset: int = 0
    ) -> dict[str, Any]:
        return {
            'binary_id': binary_id,
            'index_state': self.store.get_binary_index_state(binary_id),
            'functions': self.store.list_function_index(binary_id, filter_text, limit, offset),
        }

    def cached_strings(
        self, binary_id: str, filter_text: str = '', limit: int = 200, offset: int = 0
    ) -> dict[str, Any]:
        return {
            'binary_id': binary_id,
            'index_state': self.store.get_binary_index_state(binary_id),
            'strings': self.store.list_string_index(binary_id, filter_text, limit, offset),
        }

    def cached_structs(
        self, binary_id: str, filter_text: str = '', limit: int = 200, offset: int = 0
    ) -> dict[str, Any]:
        return {
            'binary_id': binary_id,
            'index_state': self.store.get_binary_index_state(binary_id),
            'structs': self.store.list_struct_index(binary_id, filter_text, limit, offset),
        }

    def rename(self, runtime_session_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        addr = payload.get('addr')
        new_name = payload.get('new_name')
        if not addr or not new_name:
            raise ValueError('addr and new_name are required')
        result = self.session_tool(
            runtime_session_id,
            'rename',
            {'batch': {'globals': [{'old': addr, 'new': new_name}]}}
        )
        ctx = self._session_context(runtime_session_id)
        self._record_operation(
            'rename',
            payload=payload,
            result=result,
            project_id=ctx['project_id'],
            binary_id=ctx['binary_id'],
            runtime_session_id=runtime_session_id,
            target=str(addr),
        )
        return result

    def comment(self, runtime_session_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        addr = payload.get('addr')
        comment = payload.get('comment')
        if not addr or not comment:
            raise ValueError('addr and comment are required')
        result = self.session_tool(runtime_session_id, 'set_comments', {'items': json.dumps([{'addr': addr, 'comment': comment}])})
        ctx = self._session_context(runtime_session_id)
        self._record_operation(
            'comment',
            payload=payload,
            result=result,
            project_id=ctx['project_id'],
            binary_id=ctx['binary_id'],
            runtime_session_id=runtime_session_id,
            target=str(addr),
        )
        return result


class HeadlessApiHandler(BaseHTTPRequestHandler):
    backend: HeadlessWebBackend

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, indent=2).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, body: str) -> None:
        data = body.encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get('Content-Length', '0'))
        if length <= 0:
            return {}
        return json.loads(self.rfile.read(length).decode())

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        try:
            if path == '/':
                self._html(INDEX_HTML)
                return
            if path == '/api/projects':
                self._json(200, self.backend.list_projects())
                return
            if path == '/api/sessions':
                self._json(200, self.backend.list_sessions())
                return
            if path.startswith('/api/binaries/') and path.endswith('/indexes'):
                binary_id = path.split('/')[3]
                self._json(200, self.backend.get_binary_indexes(binary_id))
                return
            if path.startswith('/api/binaries/') and path.endswith('/functions'):
                binary_id = path.split('/')[3]
                self._json(
                    200,
                    self.backend.cached_functions(
                        binary_id,
                        query.get('filter', [''])[0],
                        int(query.get('limit', ['200'])[0]),
                        int(query.get('offset', ['0'])[0]),
                    ),
                )
                return
            if path.startswith('/api/binaries/') and path.endswith('/strings'):
                binary_id = path.split('/')[3]
                self._json(
                    200,
                    self.backend.cached_strings(
                        binary_id,
                        query.get('filter', [''])[0],
                        int(query.get('limit', ['200'])[0]),
                        int(query.get('offset', ['0'])[0]),
                    ),
                )
                return
            if path.startswith('/api/binaries/') and path.endswith('/structs'):
                binary_id = path.split('/')[3]
                self._json(
                    200,
                    self.backend.cached_structs(
                        binary_id,
                        query.get('filter', [''])[0],
                        int(query.get('limit', ['200'])[0]),
                        int(query.get('offset', ['0'])[0]),
                    ),
                )
                return
            if path.startswith('/api/binaries/') and path.endswith('/history'):
                binary_id = path.split('/')[3]
                self._json(
                    200,
                    self.backend.list_history(
                        binary_id,
                        int(query.get('limit', ['100'])[0]),
                    ),
                )
                return
            if path.startswith('/api/sessions/') and path.endswith('/lookup'):
                session_id = path.split('/')[3]
                self._json(200, self.backend.lookup(session_id, query.get('query', [''])[0]))
                return
            if path.startswith('/api/sessions/') and path.endswith('/xrefs'):
                session_id = path.split('/')[3]
                self._json(
                    200,
                    self.backend.xrefs(
                        session_id,
                        query.get('addr', [''])[0],
                        int(query.get('limit', ['50'])[0]),
                    ),
                )
                return
            if path.startswith('/api/sessions/') and path.endswith('/strings'):
                session_id = path.split('/')[3]
                self._json(200, self.backend.list_strings(session_id, query.get('q', ['.'])[0], int(query.get('offset', ['0'])[0]), int(query.get('limit', ['100'])[0])))
                return
            if path.startswith('/api/sessions/') and path.endswith('/decompile'):
                session_id = path.split('/')[3]
                self._json(200, self.backend.decompile(session_id, query.get('addr', [''])[0]))
                return
            if path.startswith('/api/sessions/') and path.endswith('/disasm'):
                session_id = path.split('/')[3]
                self._json(200, self.backend.disasm(session_id, query.get('addr', [''])[0]))
                return
            if path.startswith('/api/sessions/') and path.endswith('/structs'):
                session_id = path.split('/')[3]
                self._json(200, self.backend.list_structs(session_id, query.get('filter', [''])[0]))
                return
            self._json(404, {'error': f'unknown route: {path}'})
        except Exception as exc:
            logger.exception('GET %s failed', path)
            self._json(500, {'error': str(exc)})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            payload = self._read_json()
            if path == '/api/projects':
                self._json(200, self.backend.create_project(payload))
                return
            if path.startswith('/api/projects/') and path.endswith('/binaries'):
                project_id = path.split('/')[3]
                self._json(200, self.backend.add_binary(project_id, payload))
                return
            if path.startswith('/api/projects/') and path.endswith('/restore-artifact'):
                project_id = path.split('/')[3]
                self._json(200, self.backend.restore_artifact(project_id, payload))
                return
            if path.startswith('/api/binaries/') and path.endswith('/sessions'):
                binary_id = path.split('/')[3]
                self._json(200, self.backend.open_session(binary_id))
                return
            if path.startswith('/api/binaries/') and path.endswith('/refresh-indexes'):
                binary_id = path.split('/')[3]
                self._json(
                    200,
                    self.backend.refresh_indexes(binary_id, payload.get('session_id')),
                )
                return
            if path.startswith('/api/sessions/') and path.endswith('/close'):
                session_id = path.split('/')[3]
                self._json(200, self.backend.close_session(session_id))
                return
            if path.startswith('/api/sessions/') and path.endswith('/rename'):
                session_id = path.split('/')[3]
                self._json(200, self.backend.rename(session_id, payload))
                return
            if path.startswith('/api/sessions/') and path.endswith('/comment'):
                session_id = path.split('/')[3]
                self._json(200, self.backend.comment(session_id, payload))
                return
            if path.startswith('/api/sessions/') and path.endswith('/patch-bytes'):
                session_id = path.split('/')[3]
                self._json(200, self.backend.patch_bytes(session_id, payload))
                return
            if path.startswith('/api/sessions/') and path.endswith('/patch-asm'):
                session_id = path.split('/')[3]
                self._json(200, self.backend.patch_asm(session_id, payload))
                return
            if path.startswith('/api/sessions/') and path.endswith('/set-type'):
                session_id = path.split('/')[3]
                self._json(200, self.backend.apply_type(session_id, payload))
                return
            if path.startswith('/api/sessions/') and path.endswith('/read-struct'):
                session_id = path.split('/')[3]
                self._json(200, self.backend.read_struct(session_id, payload))
                return
            if path.startswith('/api/sessions/') and path.endswith('/declare-struct'):
                session_id = path.split('/')[3]
                self._json(200, self.backend.declare_struct(session_id, payload))
                return
            if path.startswith('/api/sessions/') and path.endswith('/tool'):
                session_id = path.split('/')[3]
                self._json(200, self.backend.session_tool(session_id, payload['tool_name'], payload.get('arguments', {})))
                return
            self._json(404, {'error': f'unknown route: {path}'})
        except Exception as exc:
            logger.exception('POST %s failed', path)
            self._json(500, {'error': str(exc)})

    def log_message(self, format: str, *args: Any) -> None:
        logger.info('%s - %s', self.address_string(), format % args)


def main() -> None:
    parser = argparse.ArgumentParser(description='Headless IDA project/session web manager')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--db', type=Path, default=Path('.ida-headless/projects.sqlite3'))
    parser.add_argument('--project-name', default='default')
    parser.add_argument('--artifact', action='append', default=[], help='Artifact (.i64/.idb/binary) to restore on startup; may be repeated')
    parser.add_argument('--open-session', action='store_true', help='Open a live session for startup artifacts')
    parser.add_argument('--refresh-on-start', action='store_true', help='Refresh indexes for startup artifacts after opening sessions')
    parser.add_argument('--unsafe', action='store_true')
    parser.add_argument('--verbose', '-v', action='store_true')
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    )

    backend = HeadlessWebBackend(args.db, unsafe=args.unsafe, verbose=args.verbose)
    atexit.register(backend.shutdown)

    if args.artifact:
        boot = backend.bootstrap_artifacts(
            args.project_name,
            args.artifact,
            root_dir=Path.cwd(),
            open_session=args.open_session or args.refresh_on_start,
            refresh_indexes=args.refresh_on_start,
        )
        logger.info(
            'Bootstrapped %d artifact(s) into project %s',
            len(boot['items']),
            boot['project']['name'],
        )

    handler = type('BoundHeadlessApiHandler', (HeadlessApiHandler,), {'backend': backend})
    server = ThreadingHTTPServer((args.host, args.port), handler)
    logger.info('Headless web manager listening on http://%s:%d', args.host, args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        backend.shutdown()


if __name__ == '__main__':
    main()
