from __future__ import annotations

import argparse
import atexit
import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from websockets.sync.server import ServerConnection, serve

from ida_pro_mcp.headless_project_store import HeadlessProjectStore
from ida_pro_mcp.session_mcp_server import SessionMcpServer

logger = logging.getLogger(__name__)


class LiveUpdateHub:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self._clients: set[ServerConnection] = set()
        self._lock = threading.Lock()
        self._server = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name='headless-web-ws', daemon=True)
        self._thread.start()
        self._ready.wait(timeout=5)

    def _run(self) -> None:
        with serve(self._handler, self.host, self.port) as server:
            self._server = server
            self._ready.set()
            logger.info('Live update websocket listening on ws://%s:%d/ws', self.host, self.port)
            server.serve_forever()

    def _handler(self, websocket: ServerConnection) -> None:
        with self._lock:
            self._clients.add(websocket)
        try:
            for _message in websocket:
                pass
        except Exception:
            pass
        finally:
            with self._lock:
                self._clients.discard(websocket)

    def publish(self, payload: dict[str, Any]) -> None:
        message = json.dumps(payload)
        with self._lock:
            clients = list(self._clients)
        stale: list[ServerConnection] = []
        for websocket in clients:
            try:
                websocket.send(message)
            except Exception:
                stale.append(websocket)
        if stale:
            with self._lock:
                for websocket in stale:
                    self._clients.discard(websocket)

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=1)


DASHBOARD_HTML = """<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>IDA Dashboard</title>
<style>
:root {
  --bg: #1e1e1e; --panel: #252526; --panel2: #2d2d30; --border: #3c3c3c;
  --text: #d4d4d4; --muted: #9da5b4; --accent: #0e639c; --success: #2ea043;
  --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:13px/1.4 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; }
button,input { font:inherit; }
button { cursor:pointer; border:1px solid var(--border); background:var(--panel2); color:var(--text); border-radius:6px; padding:8px 10px; }
button.primary { background:var(--accent); border-color:#1177bb; }
input { width:100%; border:1px solid var(--border); background:#1f1f1f; color:var(--text); border-radius:6px; padding:8px 10px; }
header { display:flex; align-items:center; justify-content:space-between; padding:14px 16px; border-bottom:1px solid var(--border); background:#181818; }
main { padding:16px; display:grid; grid-template-columns: 320px 1fr; gap:16px; min-height: calc(100vh - 58px); }
.sidebar, .content { min-width:0; }
.panel { border:1px solid var(--border); background:var(--panel); border-radius:10px; overflow:hidden; margin-bottom:16px; }
.panel-header { display:flex; align-items:center; justify-content:space-between; gap:8px; padding:10px 12px; border-bottom:1px solid var(--border); background:#26272b; }
.panel-title { font-size:12px; text-transform:uppercase; letter-spacing:.04em; color:var(--muted); }
.panel-body { padding:12px; }
.row { display:flex; gap:8px; align-items:center; }
.row.wrap { flex-wrap:wrap; }
.stack { display:flex; flex-direction:column; gap:10px; }
.project-card, .binary-card { border:1px solid var(--border); border-radius:8px; padding:10px; background:#202124; }
.project-card.active { outline:2px solid #3794ff; }
.binary-card { margin-top:8px; }
.badge { display:inline-flex; align-items:center; border:1px solid var(--border); border-radius:999px; padding:2px 8px; font-size:11px; color:var(--muted); }
.badge.success { color:#9be9a8; border-color:rgba(46,160,67,.55); }
.small { font-size:12px; color:var(--muted); }
.mono { font-family: var(--mono); }
.actions { display:flex; gap:8px; flex-wrap:wrap; margin-top:10px; }
.summary-grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap:12px; }
.summary-card { border:1px solid var(--border); border-radius:8px; background:#202124; padding:12px; }
.empty { border:1px dashed var(--border); border-radius:8px; padding:18px; color:var(--muted); }
pre { margin:0; white-space:pre-wrap; word-break:break-word; font-family:var(--mono); font-size:12px; }
</style>
</head>
<body>
<header>
  <div><strong>IDA Dashboard</strong> <span class='small'>projects · binaries · sessions</span></div>
  <div id='dashStatus' class='small'>Ready.</div>
</header>
<main>
  <aside class='sidebar'>
    <section class='panel'>
      <div class='panel-header'><div class='panel-title'>Create Project</div></div>
      <div class='panel-body stack'>
        <input id='projectName' placeholder='Project name'>
        <button class='primary' onclick='createProject()'>Create</button>
      </div>
    </section>
    <section class='panel'>
      <div class='panel-header'><div class='panel-title'>Import Artifact</div></div>
      <div class='panel-body stack'>
        <input id='artifactPath' placeholder='/path/to/binary or .i64'>
        <div class='small'>Selected project: <span id='selectedProjectName'>none</span></div>
        <div class='row'>
          <button onclick='addBinary()'>Add Binary</button>
          <button onclick='restoreArtifact()'>Restore</button>
        </div>
      </div>
    </section>
    <section class='panel'>
      <div class='panel-header'><div class='panel-title'>Projects</div><button onclick='refreshDashboard()'>Refresh</button></div>
      <div class='panel-body'><div id='projectList' class='stack'></div></div>
    </section>
  </aside>
  <section class='content'>
    <section class='panel'>
      <div class='panel-header'><div class='panel-title'>Overview</div></div>
      <div class='panel-body'><div id='summaryGrid' class='summary-grid'></div></div>
    </section>
    <section class='panel'>
      <div class='panel-header'><div class='panel-title'>Selected Project</div></div>
      <div class='panel-body'><div id='projectDetail'></div></div>
    </section>
  </section>
</main>
<script>
const LIVE_WS_PORT = __LIVE_WS_PORT__;
const LIVE_WS_URL = LIVE_WS_PORT ? `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.hostname}:${LIVE_WS_PORT}/ws` : null;
const dashState = { projects: [], sessions: [], selectedProjectId: null };
let dashSocket = null;
let dashRefreshTimer = null;
function esc(v){ return String(v ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }
function setDashStatus(msg){ document.getElementById('dashStatus').textContent = msg; }
async function api(path, options={}) {
  const response = await fetch(path, { headers:{'Content-Type':'application/json'}, ...options });
  const text = await response.text();
  const payload = text ? JSON.parse(text) : {};
  if (!response.ok) throw new Error(payload.error || response.statusText);
  return payload;
}
function selectedProject(){ return dashState.projects.find(p => p.project_id === dashState.selectedProjectId) || null; }
function liveSessionForBinary(binaryId){ return dashState.sessions.find(s => s.binary_id === binaryId && s.live); }
function renderSummary(){
  const totalProjects = dashState.projects.length;
  const totalBinaries = dashState.projects.reduce((n,p)=>n+(p.binaries||[]).length,0);
  const totalLive = dashState.sessions.filter(s => s.live).length;
  document.getElementById('summaryGrid').innerHTML = [
    ['Projects', totalProjects], ['Binaries', totalBinaries], ['Live sessions', totalLive]
  ].map(([k,v]) => `<div class='summary-card'><div class='small'>${esc(k)}</div><div style='font-size:28px;font-weight:700;margin-top:6px;'>${esc(v)}</div></div>`).join('');
}
function renderProjects(){
  const list = document.getElementById('projectList');
  if (!dashState.projects.length) { list.innerHTML = `<div class='empty'>No projects yet.</div>`; return; }
  list.innerHTML = dashState.projects.map((project) => `
    <div class='project-card ${project.project_id === dashState.selectedProjectId ? 'active' : ''}' onclick="selectProject('${project.project_id}')">
      <div class='row' style='justify-content:space-between;'><strong>${esc(project.name)}</strong><span class='badge'>${project.binary_count} bin</span></div>
      <div class='small'>${esc(project.root_dir || '')}</div>
    </div>`).join('');
  document.getElementById('selectedProjectName').textContent = selectedProject()?.name || 'none';
}
function renderProjectDetail(){
  const project = selectedProject();
  const target = document.getElementById('projectDetail');
  if (!project) { target.innerHTML = `<div class='empty'>Select a project.</div>`; return; }
  const binaries = project.binaries || [];
  if (!binaries.length) { target.innerHTML = `<div class='empty'>Project has no binaries yet.</div>`; return; }
  target.innerHTML = binaries.map((binary) => {
    const live = liveSessionForBinary(binary.binary_id);
    return `
      <div class='binary-card'>
        <div class='row' style='justify-content:space-between;align-items:flex-start;'>
          <div>
            <div><strong>${esc(binary.display_name)}</strong></div>
            <div class='small mono'>${esc(binary.idb_path || binary.binary_path)}</div>
          </div>
          <span class='badge ${live ? 'success' : ''}'>${live ? 'live' : 'idle'}</span>
        </div>
        <div class='actions'>
          <button onclick="openWorkspace('${binary.binary_id}')">Open Workspace</button>
          <button onclick="startSession('${binary.binary_id}')">Start Session</button>
          <button onclick="refreshIndexes('${binary.binary_id}')">Refresh Indexes</button>
        </div>
      </div>`;
  }).join('');
}
function selectProject(projectId){ dashState.selectedProjectId = projectId; renderProjects(); renderProjectDetail(); }
function openWorkspace(binaryId){ window.location.href = `/workspace/${binaryId}`; }
function scheduleDashRefresh(reason) {
  window.clearTimeout(dashRefreshTimer);
  dashRefreshTimer = window.setTimeout(async () => {
    await refreshDashboard();
    if (reason) setDashStatus(`Live update: ${reason}`);
  }, 220);
}
function connectDashLiveUpdates() {
  if (!LIVE_WS_URL) return;
  dashSocket = new WebSocket(LIVE_WS_URL);
  dashSocket.onmessage = (event) => {
    try {
      const payload = JSON.parse(event.data);
      scheduleDashRefresh(payload.operation_type || payload.event || 'update');
    } catch (_err) {}
  };
  dashSocket.onclose = () => { window.setTimeout(connectDashLiveUpdates, 1500); };
  dashSocket.onerror = () => dashSocket && dashSocket.close();
}
async function refreshDashboard(){
  const [projects, sessions] = await Promise.all([api('/api/projects'), api('/api/sessions')]);
  dashState.projects = projects.projects || [];
  dashState.sessions = sessions.sessions || [];
  if (dashState.selectedProjectId && !dashState.projects.find(p => p.project_id === dashState.selectedProjectId)) dashState.selectedProjectId = null;
  if (!dashState.selectedProjectId && dashState.projects.length) dashState.selectedProjectId = dashState.projects[0].project_id;
  renderSummary(); renderProjects(); renderProjectDetail();
}
async function createProject(){
  const name = document.getElementById('projectName').value.trim();
  if (!name) return setDashStatus('Project name required.');
  const result = await api('/api/projects', { method:'POST', body: JSON.stringify({name}) });
  document.getElementById('projectName').value = '';
  dashState.selectedProjectId = result.project.project_id;
  await refreshDashboard();
  setDashStatus(`Created ${result.project.name}`);
}
async function addBinary(){
  if (!dashState.selectedProjectId) return setDashStatus('Select a project first.');
  const binary_path = document.getElementById('artifactPath').value.trim();
  if (!binary_path) return setDashStatus('Binary path required.');
  await api(`/api/projects/${dashState.selectedProjectId}/binaries`, { method:'POST', body: JSON.stringify({binary_path}) });
  document.getElementById('artifactPath').value = '';
  await refreshDashboard();
  setDashStatus('Binary added.');
}
async function restoreArtifact(){
  if (!dashState.selectedProjectId) return setDashStatus('Select a project first.');
  const artifact_path = document.getElementById('artifactPath').value.trim();
  if (!artifact_path) return setDashStatus('Artifact path required.');
  await api(`/api/projects/${dashState.selectedProjectId}/restore-artifact`, { method:'POST', body: JSON.stringify({artifact_path}) });
  document.getElementById('artifactPath').value = '';
  await refreshDashboard();
  setDashStatus('Artifact restored.');
}
async function startSession(binaryId){
  await api(`/api/binaries/${binaryId}/sessions`, { method:'POST' });
  await refreshDashboard();
  setDashStatus('Session started.');
}
async function refreshIndexes(binaryId){
  await api(`/api/binaries/${binaryId}/refresh-indexes`, { method:'POST', body: '{}' });
  await refreshDashboard();
  setDashStatus('Indexes refreshed.');
}
window.addEventListener('load', async () => {
  try { connectDashLiveUpdates(); await refreshDashboard(); setDashStatus('Dashboard ready.'); } catch (err) { setDashStatus(err.message); }
});
</script>
</body>
</html>
"""

WORKSPACE_HTML = """<!doctype html>
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
  grid-template-columns: 380px minmax(420px, 1fr) 300px;
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
  overflow: hidden;
  padding: 10px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.sidebar .column { padding-right: 8px; }
.inspector .column { overflow: auto; }
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
.panel.compact .panel-body { padding: 8px 10px; }
.projects-panel .panel-body { max-height: 180px; overflow: auto; }
.explorer-panel .panel-body { display: flex; flex-direction: column; gap: 10px; min-height: 0; height: 100%; }
#resourceList { flex: 1; min-height: 0; overflow: auto; }
.workspace-summary { display: flex; flex-wrap: wrap; gap: 8px; }
.summary-chip { flex: 1 1 140px; min-width: 0; border: 1px solid var(--border); border-radius: 6px; background: #1b1c1f; padding: 8px 10px; }
.summary-chip .label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }
.summary-chip .value { margin-top: 4px; font-family: var(--mono); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
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
        <section class='panel compact workspace-panel'>
          <div class='panel-header'>
            <div class='panel-title'>Workspace</div>
            <span id='sessionBadge' class='badge warn'>No live session</span>
          </div>
          <div class='panel-body'>
            <div id='workspaceMeta' class='workspace-summary'></div>
          </div>
        </section>

        <section class='panel projects-panel'>
          <div class='panel-header'>
            <div class='panel-title'>Projects</div>
            <button class='ghost' onclick='refreshWorkspace()'>Refresh</button>
          </div>
          <div class='panel-body'>
            <div id='projectTree' class='tree'></div>
          </div>
        </section>

        <section class='panel fill explorer-panel'>
          <div class='panel-header'>
            <div class='panel-title'>Explorer</div>
            <div id='indexBadges' class='row wrap'></div>
          </div>
          <div class='panel-body'>
            <div class='segmented'>
              <button id='resource-functions' onclick="setResourceMode('functions')">Functions</button>
              <button id='resource-strings' onclick="setResourceMode('strings')">Strings</button>
              <button id='resource-structs' onclick="setResourceMode('structs')">Structs</button>
              <button id='resource-history' onclick="setResourceMode('history')">History</button>
            </div>
            <input id='resourceFilter' placeholder='Filter current explorer' oninput='onResourceFilterChange()'>
            <div id='resourceList' class='list'></div>
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
const INITIAL_BINARY_ID = __INITIAL_BINARY_ID__;
const LIVE_WS_PORT = __LIVE_WS_PORT__;
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
  currentResourceItems: [],
  loading: false,
  lastLiveEvent: null,
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
  const items = [
    ['Project', project ? project.name : '—'],
    ['Binary', binary ? binary.display_name : '—'],
    ['Session', state.selectedSessionId || '—'],
    ['Path', binary ? (binary.idb_path || binary.binary_path) : '—'],
  ];
  document.getElementById('workspaceMeta').innerHTML = items.map(([label, value]) => `
    <div class='summary-chip'>
      <div class='label'>${escapeHtml(label)}</div>
      <div class='value'>${escapeHtml(value)}</div>
    </div>
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

function selectedContext() {
  return state.selectedItem?.context || {};
}

function renderInspector() {
  const binary = selectedBinary();
  const item = state.selectedItem;
  const ctx = selectedContext();
  const rows = [
    ['Kind', item?.kind || '—'],
    ['Name', item?.name || '—'],
    ['Address', item?.addr || '—'],
    ['Binary', binary?.display_name || '—'],
    ['Session', state.selectedSessionId || '—'],
    ['Live event', state.lastLiveEvent ? `${state.lastLiveEvent.operation_type || state.lastLiveEvent.event} @ ${state.lastLiveEvent.target || '—'}` : '—'],
  ];
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

async function selectFunction(item) {
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
  renderDetails(item);
  await refreshResourcePane();
  setTab('strings');
  await loadSelectionContext();
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
  renderDetails(item);
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
  renderDetails(item);
  refreshResourcePane();
  setTab('history');
}

async function lookupAndOpen() {
  const query = document.getElementById('gotoInput').value.trim();
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
            <div class='xref-item' ${canJump ? `data-jump-addr='${encodedAddr}'` : ''}>
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
            <div class='xref-item' data-jump-addr='${encodedAddr}'>
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
    connectWorkspaceLiveUpdates();
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
    def __init__(self, db_path: Path, unsafe: bool = False, verbose: bool = False, notifier: LiveUpdateHub | None = None, notify_api_url: str | None = None):
        self.store = HeadlessProjectStore(db_path)
        self.sessions = SessionMcpServer(unsafe=unsafe, verbose=verbose)
        self.notifier = notifier
        self.notify_api_url = notify_api_url

    def shutdown(self) -> None:
        self.sessions.cleanup()
        if self.notifier is not None:
            self.notifier.stop()

    def _publish_event(self, event: str, **payload: Any) -> None:
        if self.notifier is None:
            return
        self.notifier.publish({'event': event, 'ts': time.time(), **payload})

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
        self._publish_event(
            'operation',
            operation_type=operation_type,
            project_id=project_id,
            binary_id=binary_id,
            runtime_session_id=runtime_session_id,
            target=target,
        )

    @staticmethod
    def _unwrap_tool_result(value: Any) -> Any:
        current = value
        while isinstance(current, dict) and "result" in current and len(current) == 1:
            current = current["result"]
        return current

    def create_project(self, payload: dict[str, Any]) -> dict[str, Any]:
        name = (payload.get('name') or '').strip()
        if not name:
            raise ValueError('name is required')
        root_dir = payload.get('root_dir') or str(Path.cwd())
        result = {'project': self.store.create_project(name, root_dir)}
        self._record_operation('create_project', payload=payload, result=result, project_id=result['project']['project_id'], target=result['project']['name'])
        return result

    def add_binary(self, project_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        binary_path = payload.get('binary_path')
        if not binary_path:
            raise ValueError('binary_path is required')
        result = {'binary': self.store.add_binary(project_id, binary_path, payload.get('display_name'))}
        self._record_operation('add_binary', payload=payload, result=result, project_id=project_id, binary_id=result['binary']['binary_id'], target=result['binary']['display_name'])
        return result

    def notify_event(self, payload: dict[str, Any]) -> dict[str, Any]:
        event = (payload.get('event') or 'invalidate').strip() or 'invalidate'
        self._publish_event(
            event,
            project_id=payload.get('project_id'),
            binary_id=payload.get('binary_id'),
            runtime_session_id=payload.get('runtime_session_id'),
            operation_type=payload.get('operation_type'),
            target=payload.get('target'),
        )
        return {'ok': True, 'event': event}

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
        session = self.sessions.create_session(
            str(open_path),
            live_notify_url=self.notify_api_url,
            notify_project_id=binary['project_id'],
            notify_binary_id=binary_id,
        )
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

    def _resolve_function_for_addr(self, runtime_session_id: str, addr: str) -> dict[str, Any] | None:
        if not addr:
            return None
        try:
            lookup_result = self._unwrap_tool_result(
                self.sessions.call_tool('lookup_funcs', {'queries': addr}, session_id=runtime_session_id)
            )
            entry = (lookup_result or [{}])[0] if isinstance(lookup_result, list) else (lookup_result or {})
            fn = entry.get('fn') if isinstance(entry, dict) else None
            return fn if isinstance(fn, dict) and fn.get('addr') else None
        except Exception:
            return None

    def _group_rows_by_function(
        self,
        runtime_session_id: str,
        rows: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        grouped: dict[str, dict[str, Any]] = {}
        for row in rows:
            fn = row.get('fn') or {}
            if not fn:
                fn = self._resolve_function_for_addr(
                    runtime_session_id,
                    str(row.get('from') or row.get('addr') or ''),
                ) or {}
            fn_addr = str(fn.get('addr') or '')
            fn_name = str(fn.get('name') or '')
            site = str(row.get('from') or row.get('addr') or '')
            key = fn_addr or fn_name
            if not key:
                continue
            item = grouped.setdefault(
                key,
                {
                    'addr': fn_addr or site or key,
                    'name': fn_name or fn_addr or key,
                    'sites': [],
                    'types': [],
                    'count': 0,
                },
            )
            if site and site not in item['sites']:
                item['sites'].append(site)
            row_type = str(row.get('type') or '')
            if row_type and row_type not in item['types']:
                item['types'].append(row_type)
            item['count'] = len(item['sites']) or max(item['count'], 1)
        return sorted(
            grouped.values(),
            key=lambda item: (-int(item.get('count') or 0), str(item.get('name') or item.get('addr') or '')),
        )

    def context(self, runtime_session_id: str, kind: str, query: str) -> dict[str, Any]:
        if not query:
            raise ValueError('query is required')
        kind = (kind or 'lookup').strip().lower()

        if kind in {'function', 'lookup'}:
            lookup_result = self._unwrap_tool_result(
                self.sessions.call_tool('lookup_funcs', {'queries': query}, session_id=runtime_session_id)
            )
            lookup_entry = (lookup_result or [{}])[0] if isinstance(lookup_result, list) else (lookup_result or {})
            fn = lookup_entry.get('fn') or {}
            resolved_addr = str(fn.get('addr') or query)
            analysis = self._unwrap_tool_result(
                self.sessions.call_tool(
                    'analyze_function',
                    {'addr': resolved_addr, 'include_asm': False},
                    session_id=runtime_session_id,
                )
            )
            xrefs = self.xrefs(runtime_session_id, resolved_addr, limit=50).get('result', {})
            comments = analysis.get('comments') if isinstance(analysis, dict) else {}
            result = {
                'kind': 'function',
                'query': query,
                'resolved_addr': resolved_addr,
                'function': {
                    'addr': resolved_addr,
                    'name': fn.get('name') or analysis.get('name') or query,
                    'size': fn.get('size') or analysis.get('size'),
                },
                'prototype': analysis.get('prototype') if isinstance(analysis, dict) else None,
                'strings': analysis.get('strings') if isinstance(analysis, dict) else [],
                'constants': analysis.get('constants') if isinstance(analysis, dict) else [],
                'comments': comments or {},
                'comment_count': len(comments or {}),
                'callers': xrefs.get('callers') or [],
                'callees': xrefs.get('callees') or [],
                'incoming_refs': xrefs.get('incoming') or [],
                'outgoing_refs': xrefs.get('outgoing') or [],
                'analysis': analysis,
            }
            return {'session_id': runtime_session_id, 'kind': 'function', 'result': result}

        if kind == 'string':
            string_result = self._unwrap_tool_result(
                self.sessions.call_tool('get_string', {'addrs': query}, session_id=runtime_session_id)
            )
            string_entry = (string_result or [{}])[0] if isinstance(string_result, list) else (string_result or {})
            xrefs = self.xrefs(runtime_session_id, query, limit=100).get('result', {})
            incoming = list(xrefs.get('incoming') or [])
            outgoing = list(xrefs.get('outgoing') or [])
            ref_functions = self._group_rows_by_function(runtime_session_id, incoming)
            result = {
                'kind': 'string',
                'query': query,
                'resolved_addr': str(string_entry.get('addr') or query),
                'value': string_entry.get('value'),
                'error': string_entry.get('error'),
                'ref_functions': ref_functions,
                'incoming_refs': incoming,
                'outgoing_refs': outgoing,
                'ref_function_count': len(ref_functions),
            }
            return {'session_id': runtime_session_id, 'kind': 'string', 'result': result}

        raise ValueError(f'unsupported context kind: {kind}')

    def xrefs(self, runtime_session_id: str, addr: str, limit: int = 50) -> dict[str, Any]:
        if not addr:
            raise ValueError('addr is required')
        xref_result = self._unwrap_tool_result(self.sessions.call_tool(
            'xref_query',
            {
                'queries': {
                    'query': addr,
                    'direction': 'both',
                    'xref_type': 'any',
                    'offset': 0,
                    'count': max(limit * 2, limit),
                    'include_fn': True,
                    'dedup': True,
                    'sort_by': 'addr',
                    'descending': False,
                }
            },
            session_id=runtime_session_id,
        ))
        xref_entry = (xref_result or [{}])[0] if isinstance(xref_result, list) else (xref_result or {})
        xref_rows = list(xref_entry.get('data') or [])
        incoming = [row for row in xref_rows if row.get('direction') == 'to']
        outgoing = [row for row in xref_rows if row.get('direction') == 'from']

        ref_functions = self._group_rows_by_function(runtime_session_id, incoming)
        callers_map: dict[str, dict[str, Any]] = {}
        for row in incoming:
            if row.get('type') != 'code':
                continue
            fn = row.get('fn') or {}
            caller_addr = str(fn.get('addr') or row.get('from') or row.get('addr') or '')
            if not caller_addr:
                continue
            caller = callers_map.setdefault(
                caller_addr,
                {
                    'addr': caller_addr,
                    'name': fn.get('name') or caller_addr,
                    'sites': [],
                    'count': 0,
                },
            )
            site = str(row.get('from') or row.get('addr') or '')
            if site and site not in caller['sites']:
                caller['sites'].append(site)
            caller['count'] = len(caller['sites'])

        callees_map: dict[str, dict[str, Any]] = {}
        resolved_addr = str(xref_entry.get('resolved_addr') or addr)
        try:
            callgraph = self._unwrap_tool_result(self.sessions.call_tool(
                'callgraph',
                {
                    'roots': resolved_addr,
                    'max_depth': 1,
                    'max_nodes': max(limit + 1, 16),
                    'max_edges': max(limit * 4, 32),
                },
                session_id=runtime_session_id,
            ))
            callgraph_entry = (callgraph or [{}])[0] if isinstance(callgraph, list) else (callgraph or {})
            nodes = {
                str(node.get('addr')): node
                for node in (callgraph_entry.get('nodes') or [])
                if isinstance(node, dict) and node.get('addr')
            }
            for edge in callgraph_entry.get('edges') or []:
                if str(edge.get('from')) != resolved_addr:
                    continue
                callee_addr = str(edge.get('to') or '')
                if not callee_addr:
                    continue
                node = nodes.get(callee_addr, {})
                callee = callees_map.setdefault(
                    callee_addr,
                    {
                        'addr': callee_addr,
                        'name': node.get('name') or edge.get('name') or callee_addr,
                        'count': 0,
                    },
                )
                callee['count'] += 1
        except Exception:
            pass

        return {
            'session_id': runtime_session_id,
            'tool': 'xref_query+callgraph',
            'result': {
                'resolved_addr': resolved_addr,
                'incoming': incoming,
                'outgoing': outgoing,
                'ref_functions': ref_functions,
                'callers': list(callers_map.values()),
                'callees': list(callees_map.values()),
                'total': len(xref_rows),
            },
        }

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

    def _dashboard_html(self) -> str:
        return DASHBOARD_HTML.replace('__LIVE_WS_PORT__', str(self.ws_port))

    def _workspace_html(self, binary_id: str) -> str:
        self.backend._require_binary(binary_id)
        return (
            WORKSPACE_HTML
            .replace('__INITIAL_BINARY_ID__', json.dumps(binary_id))
            .replace('__LIVE_WS_PORT__', str(self.ws_port))
        )

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
                self._html(self._dashboard_html())
                return
            if path.startswith('/workspace/'):
                binary_id = path.split('/')[2]
                self._html(self._workspace_html(binary_id))
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
            if path.startswith('/api/sessions/') and path.endswith('/context'):
                session_id = path.split('/')[3]
                self._json(
                    200,
                    self.backend.context(
                        session_id,
                        query.get('kind', ['lookup'])[0],
                        query.get('query', [''])[0],
                    ),
                )
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
            if path == '/api/live/notify':
                self._json(200, self.backend.notify_event(payload))
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
    parser.add_argument('--ws-port', type=int, default=None)
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

    ws_port = args.ws_port if args.ws_port is not None else args.port + 1
    notifier = LiveUpdateHub(args.host, ws_port)
    notifier.start()

    notify_api_url = f'http://{args.host}:{args.port}/api/live/notify'
    backend = HeadlessWebBackend(
        args.db,
        unsafe=args.unsafe,
        verbose=args.verbose,
        notifier=notifier,
        notify_api_url=notify_api_url,
    )
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

    handler = type('BoundHeadlessApiHandler', (HeadlessApiHandler,), {'backend': backend, 'ws_port': ws_port})
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
