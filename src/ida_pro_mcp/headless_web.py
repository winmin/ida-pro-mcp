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

INDEX_HTML = '''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IDA Headless Manager</title>
<style>
body { margin: 0; font-family: system-ui, sans-serif; background: #111827; color: #e5e7eb; }
header { padding: 12px 16px; border-bottom: 1px solid #374151; display: flex; gap: 12px; align-items: center; }
main { display: grid; grid-template-columns: 320px 1fr; height: calc(100vh - 58px); }
aside { border-right: 1px solid #374151; overflow: auto; padding: 12px; }
section { padding: 12px; overflow: auto; }
.card { background: #1f2937; border: 1px solid #374151; border-radius: 8px; padding: 10px; margin-bottom: 10px; }
button,input,textarea,select { background: #0f172a; color: #e5e7eb; border: 1px solid #475569; border-radius: 6px; padding: 8px; }
button { cursor: pointer; }
button:hover { background: #1e293b; }
pre { white-space: pre-wrap; word-break: break-word; background: #0b1220; padding: 12px; border-radius: 8px; }
.small { color: #94a3b8; font-size: 12px; }
.row { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
.tabs { display: flex; gap: 8px; margin: 12px 0; }
.list { display: grid; gap: 8px; }
.active { outline: 2px solid #38bdf8; }
</style>
</head>
<body>
<header>
  <strong>IDA Headless Manager</strong>
  <span class="small">Project / Binary / Session / Strings / Decompile / Disasm / Structs</span>
</header>
<main>
  <aside>
    <div class="card">
      <div class="row">
        <input id="projectName" placeholder="New project name">
        <button onclick="createProject()">Create</button>
      </div>
    </div>
    <div id="projects" class="list"></div>
  </aside>
  <section>
    <div class="card">
      <div class="row">
        <input id="binaryPath" style="min-width:320px" placeholder="/path/to/binary or .i64">
        <button onclick="addBinary()">Add Binary</button>
        <button onclick="openSession()">Start Session</button>
        <button onclick="refreshAll()">Refresh</button>
      </div>
      <div class="small" id="selectionLabel">No binary selected</div>
    </div>
    <div class="card">
      <div class="row">
        <label>Session:</label>
        <select id="sessionSelect" onchange="selectSession(this.value)"></select>
        <input id="addrInput" placeholder="0x401000 / function addr">
        <input id="structFilter" placeholder="struct filter / string regex">
      </div>
      <div class="tabs">
        <button onclick="loadStrings()">Strings</button>
        <button onclick="loadDecompile()">Decompile</button>
        <button onclick="loadDisasm()">Disasm</button>
        <button onclick="loadStructs()">Structs</button>
      </div>
    </div>
    <div class="card">
      <div class="row">
        <input id="renameAddr" placeholder="rename addr">
        <input id="renameNew" placeholder="new name">
        <button onclick="renameSymbol()">Rename</button>
      </div>
      <div class="row" style="margin-top:8px;">
        <input id="commentAddr" placeholder="comment addr">
        <input id="commentText" style="min-width:320px" placeholder="comment text">
        <button onclick="setComment()">Comment</button>
      </div>
    </div>
    <pre id="output">Ready.</pre>
  </section>
</main>
<script>
let selectedProjectId = null;
let selectedBinaryId = null;
let selectedSessionId = null;

async function api(path, opts={}) {
  const res = await fetch(path, {headers: {'Content-Type':'application/json'}, ...opts});
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || JSON.stringify(data));
  return data;
}

function renderProjects(data) {
  const root = document.getElementById('projects');
  root.innerHTML = '';
  for (const project of data.projects) {
    const el = document.createElement('div');
    el.className = 'card' + (project.project_id === selectedProjectId ? ' active' : '');
    el.innerHTML = `<div class="row"><strong>${project.name}</strong><span class="small">${project.binary_count} bins / ${project.live_session_count} live</span></div>`;
    el.onclick = async () => {
      selectedProjectId = project.project_id;
      selectedBinaryId = null;
      await refreshAll();
    };
    root.appendChild(el);
    if (project.binaries) {
      for (const binary of project.binaries) {
        const child = document.createElement('div');
        child.className = 'card' + (binary.binary_id === selectedBinaryId ? ' active' : '');
        child.style.marginLeft = '12px';
        child.innerHTML = `<div>${binary.display_name}</div><div class="small">${binary.binary_path}</div>`;
        child.onclick = async (ev) => {
          ev.stopPropagation();
          selectedProjectId = project.project_id;
          selectedBinaryId = binary.binary_id;
          await refreshAll();
        };
        root.appendChild(child);
      }
    }
  }
}

async function refreshAll() {
  const data = await api('/api/projects');
  renderProjects(data);
  const sessions = await api('/api/sessions');
  const select = document.getElementById('sessionSelect');
  select.innerHTML = '<option value="">-- no session --</option>';
  for (const session of sessions.sessions) {
    const opt = document.createElement('option');
    opt.value = session.runtime_session_id;
    opt.textContent = `${session.binary_name} :: ${session.runtime_session_id} (${session.status})`;
    if (session.runtime_session_id === selectedSessionId) opt.selected = true;
    select.appendChild(opt);
  }
  const label = document.getElementById('selectionLabel');
  label.textContent = selectedBinaryId ? `Selected binary: ${selectedBinaryId}` : 'No binary selected';
}

async function createProject() {
  const name = document.getElementById('projectName').value.trim();
  if (!name) return;
  const data = await api('/api/projects', {method: 'POST', body: JSON.stringify({name})});
  selectedProjectId = data.project.project_id;
  await refreshAll();
}

async function addBinary() {
  if (!selectedProjectId) throw new Error('Select a project first');
  const binary_path = document.getElementById('binaryPath').value.trim();
  const data = await api(`/api/projects/${selectedProjectId}/binaries`, {method: 'POST', body: JSON.stringify({binary_path})});
  selectedBinaryId = data.binary.binary_id;
  await refreshAll();
}

async function openSession() {
  if (!selectedBinaryId) throw new Error('Select a binary first');
  const data = await api(`/api/binaries/${selectedBinaryId}/sessions`, {method: 'POST'});
  selectedSessionId = data.session.runtime_session_id;
  await refreshAll();
  document.getElementById('output').textContent = JSON.stringify(data, null, 2);
}

function selectSession(id) { selectedSessionId = id || null; }

async function loadStrings() {
  const q = encodeURIComponent(document.getElementById('structFilter').value || '.');
  const data = await api(`/api/sessions/${selectedSessionId}/strings?q=${q}`);
  document.getElementById('output').textContent = JSON.stringify(data, null, 2);
}

async function loadDecompile() {
  const addr = encodeURIComponent(document.getElementById('addrInput').value.trim());
  const data = await api(`/api/sessions/${selectedSessionId}/decompile?addr=${addr}`);
  document.getElementById('output').textContent = typeof data.pseudocode === 'string' ? data.pseudocode : JSON.stringify(data, null, 2);
}

async function loadDisasm() {
  const addr = encodeURIComponent(document.getElementById('addrInput').value.trim());
  const data = await api(`/api/sessions/${selectedSessionId}/disasm?addr=${addr}`);
  document.getElementById('output').textContent = JSON.stringify(data, null, 2);
}

async function loadStructs() {
  const filter = encodeURIComponent(document.getElementById('structFilter').value || '');
  const data = await api(`/api/sessions/${selectedSessionId}/structs?filter=${filter}`);
  document.getElementById('output').textContent = JSON.stringify(data, null, 2);
}

async function renameSymbol() {
  const addr = document.getElementById('renameAddr').value.trim();
  const new_name = document.getElementById('renameNew').value.trim();
  const data = await api(`/api/sessions/${selectedSessionId}/rename`, {method: 'POST', body: JSON.stringify({addr, new_name})});
  document.getElementById('output').textContent = JSON.stringify(data, null, 2);
}

async function setComment() {
  const addr = document.getElementById('commentAddr').value.trim();
  const comment = document.getElementById('commentText').value.trim();
  const data = await api(`/api/sessions/${selectedSessionId}/comment`, {method: 'POST', body: JSON.stringify({addr, comment})});
  document.getElementById('output').textContent = JSON.stringify(data, null, 2);
}

refreshAll().catch(err => document.getElementById('output').textContent = String(err));
</script>
</body>
</html>
'''


class HeadlessWebBackend:
    def __init__(self, db_path: Path, unsafe: bool = False, verbose: bool = False):
        self.store = HeadlessProjectStore(db_path)
        self.sessions = SessionMcpServer(unsafe=unsafe, verbose=verbose)

    def shutdown(self) -> None:
        self.sessions.cleanup()

    def list_projects(self) -> dict[str, Any]:
        projects = self.store.list_projects()
        for project in projects:
            project['binaries'] = self.store.list_binaries(project['project_id'])
        return {'projects': projects}

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

    def open_session(self, binary_id: str) -> dict[str, Any]:
        binary = self.store.get_binary(binary_id)
        if binary is None:
            raise KeyError(f'binary not found: {binary_id}')
        session = self.sessions.create_session(binary['binary_path'])
        self.store.record_session_open(
            project_id=binary['project_id'],
            binary_id=binary_id,
            runtime_session_id=session['session_id'],
            worker_port=session.get('port'),
            worker_pid=session.get('pid'),
            status=session.get('status', 'ready'),
            metadata={'binary_path': binary['binary_path']},
        )
        idb_path = Path(binary['binary_path'])
        if idb_path.suffix.lower() not in {'.i64', '.idb'}:
            idb_path = idb_path.with_suffix('.i64')
        self.store.update_binary_idb_path(binary_id, idb_path)
        return {'session': self.store.get_session(session['session_id']), 'live': session}

    def close_session(self, runtime_session_id: str) -> dict[str, Any]:
        ok = self.sessions.close_session(runtime_session_id)
        if ok:
            self.store.record_session_close(runtime_session_id)
        return {'ok': ok, 'session_id': runtime_session_id}

    def list_sessions(self) -> dict[str, Any]:
        live_map = {s['session_id']: s for s in self.sessions.list_session_records()}
        items = self.store.list_sessions(include_closed=False)
        for item in items:
            item['live'] = live_map.get(item['runtime_session_id'])
        return {'sessions': items}

    def session_tool(self, runtime_session_id: str, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        result = self.sessions.call_tool(tool_name, arguments, session_id=runtime_session_id)
        return {'session_id': runtime_session_id, 'tool': tool_name, 'result': result}

    def list_strings(self, runtime_session_id: str, query: str, offset: int = 0, limit: int = 100) -> dict[str, Any]:
        return self.session_tool(runtime_session_id, 'find_regex', {'pattern': query or '.', 'offset': offset, 'limit': limit})

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

    def rename(self, runtime_session_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        addr = payload.get('addr')
        new_name = payload.get('new_name')
        if not addr or not new_name:
            raise ValueError('addr and new_name are required')
        return self.session_tool(
            runtime_session_id,
            'rename',
            {'batch': {'globals': [{'old': addr, 'new': new_name}]}}
        )

    def comment(self, runtime_session_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        addr = payload.get('addr')
        comment = payload.get('comment')
        if not addr or not comment:
            raise ValueError('addr and comment are required')
        return self.session_tool(runtime_session_id, 'set_comments', {'items': json.dumps([{'addr': addr, 'comment': comment}])})


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
            if path.startswith('/api/binaries/') and path.endswith('/sessions'):
                binary_id = path.split('/')[3]
                self._json(200, self.backend.open_session(binary_id))
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
    parser.add_argument('--unsafe', action='store_true')
    parser.add_argument('--verbose', '-v', action='store_true')
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    )

    backend = HeadlessWebBackend(args.db, unsafe=args.unsafe, verbose=args.verbose)
    atexit.register(backend.shutdown)

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
