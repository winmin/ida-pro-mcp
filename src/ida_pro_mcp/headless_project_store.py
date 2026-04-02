from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


def _json_load(blob: str | None) -> dict[str, Any]:
    if not blob:
        return {}
    try:
        value = json.loads(blob)
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


@dataclass(slots=True)
class ProjectRecord:
    project_id: str
    name: str
    root_dir: str
    created_at: str
    updated_at: str
    metadata: dict[str, Any]


@dataclass(slots=True)
class BinaryRecord:
    binary_id: str
    project_id: str
    binary_path: str
    display_name: str
    idb_path: str | None
    created_at: str
    updated_at: str
    metadata: dict[str, Any]


@dataclass(slots=True)
class SessionRecord:
    session_row_id: str
    project_id: str
    binary_id: str
    runtime_session_id: str
    worker_port: int | None
    worker_pid: int | None
    status: str
    created_at: str
    updated_at: str
    ended_at: str | None
    metadata: dict[str, Any]


class HeadlessProjectStore:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                '''
                PRAGMA journal_mode=WAL;
                PRAGMA foreign_keys=ON;

                CREATE TABLE IF NOT EXISTS projects (
                    project_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    root_dir TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS binaries (
                    binary_id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    binary_path TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    idb_path TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    FOREIGN KEY(project_id) REFERENCES projects(project_id) ON DELETE CASCADE
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_binaries_project_path
                ON binaries(project_id, binary_path);

                CREATE TABLE IF NOT EXISTS sessions (
                    session_row_id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    binary_id TEXT NOT NULL,
                    runtime_session_id TEXT NOT NULL,
                    worker_port INTEGER,
                    worker_pid INTEGER,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    ended_at TEXT,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    FOREIGN KEY(project_id) REFERENCES projects(project_id) ON DELETE CASCADE,
                    FOREIGN KEY(binary_id) REFERENCES binaries(binary_id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_sessions_binary_id ON sessions(binary_id);
                CREATE INDEX IF NOT EXISTS idx_sessions_runtime_session_id ON sessions(runtime_session_id);
                '''
            )

    def create_project(self, name: str, root_dir: str | Path) -> dict[str, Any]:
        project_id = uuid.uuid4().hex[:12]
        now = utcnow_iso()
        root_dir = str(Path(root_dir).expanduser().resolve())
        with self._connect() as conn:
            conn.execute(
                '''
                INSERT INTO projects(project_id, name, root_dir, created_at, updated_at, metadata_json)
                VALUES (?, ?, ?, ?, ?, '{}')
                ''',
                (project_id, name, root_dir, now, now),
            )
        return self.get_project(project_id)

    def list_projects(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                '''
                SELECT p.*, 
                       (SELECT COUNT(*) FROM binaries b WHERE b.project_id = p.project_id) AS binary_count,
                       (SELECT COUNT(*) FROM sessions s WHERE s.project_id = p.project_id AND s.ended_at IS NULL) AS live_session_count
                FROM projects p
                ORDER BY p.created_at DESC
                '''
            ).fetchall()
        return [
            {
                'project_id': row['project_id'],
                'name': row['name'],
                'root_dir': row['root_dir'],
                'created_at': row['created_at'],
                'updated_at': row['updated_at'],
                'metadata': _json_load(row['metadata_json']),
                'binary_count': row['binary_count'],
                'live_session_count': row['live_session_count'],
            }
            for row in rows
        ]

    def get_project(self, project_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute('SELECT * FROM projects WHERE project_id = ?', (project_id,)).fetchone()
        if row is None:
            return None
        return {
            'project_id': row['project_id'],
            'name': row['name'],
            'root_dir': row['root_dir'],
            'created_at': row['created_at'],
            'updated_at': row['updated_at'],
            'metadata': _json_load(row['metadata_json']),
            'binaries': self.list_binaries(project_id),
        }

    def add_binary(
        self,
        project_id: str,
        binary_path: str | Path,
        display_name: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        binary_path_obj = Path(binary_path).expanduser().resolve()
        if not binary_path_obj.exists():
            raise FileNotFoundError(binary_path_obj)
        existing = self.get_binary_by_path(project_id, binary_path_obj)
        if existing is not None:
            return existing

        binary_id = uuid.uuid4().hex[:12]
        now = utcnow_iso()
        idb_path = self._guess_idb_path(binary_path_obj)
        with self._connect() as conn:
            conn.execute(
                '''
                INSERT INTO binaries(binary_id, project_id, binary_path, display_name, idb_path, created_at, updated_at, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (
                    binary_id,
                    project_id,
                    str(binary_path_obj),
                    display_name or binary_path_obj.name,
                    str(idb_path) if idb_path else None,
                    now,
                    now,
                    json.dumps(metadata or {}),
                ),
            )
        return self.get_binary(binary_id)

    def list_binaries(self, project_id: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                '''
                SELECT b.*, 
                       (SELECT COUNT(*) FROM sessions s WHERE s.binary_id = b.binary_id AND s.ended_at IS NULL) AS live_session_count
                FROM binaries b
                WHERE b.project_id = ?
                ORDER BY b.created_at DESC
                ''',
                (project_id,),
            ).fetchall()
        return [self._row_to_binary(row) | {'live_session_count': row['live_session_count']} for row in rows]

    def get_binary(self, binary_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute('SELECT * FROM binaries WHERE binary_id = ?', (binary_id,)).fetchone()
        if row is None:
            return None
        return self._row_to_binary(row)

    def get_binary_by_path(self, project_id: str, binary_path: str | Path) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                'SELECT * FROM binaries WHERE project_id = ? AND binary_path = ?',
                (project_id, str(Path(binary_path).expanduser().resolve())),
            ).fetchone()
        return self._row_to_binary(row) if row else None

    def update_binary_idb_path(self, binary_id: str, idb_path: str | Path | None) -> None:
        with self._connect() as conn:
            conn.execute(
                'UPDATE binaries SET idb_path = ?, updated_at = ? WHERE binary_id = ?',
                (str(idb_path) if idb_path else None, utcnow_iso(), binary_id),
            )

    def record_session_open(
        self,
        project_id: str,
        binary_id: str,
        runtime_session_id: str,
        worker_port: int | None,
        worker_pid: int | None,
        status: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        session_row_id = uuid.uuid4().hex[:12]
        now = utcnow_iso()
        with self._connect() as conn:
            conn.execute(
                '''
                INSERT INTO sessions(
                    session_row_id, project_id, binary_id, runtime_session_id,
                    worker_port, worker_pid, status, created_at, updated_at, ended_at, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)
                ''',
                (
                    session_row_id,
                    project_id,
                    binary_id,
                    runtime_session_id,
                    worker_port,
                    worker_pid,
                    status,
                    now,
                    now,
                    json.dumps(metadata or {}),
                ),
            )
        return self.get_session(runtime_session_id)

    def record_session_close(self, runtime_session_id: str, status: str = 'closed') -> None:
        now = utcnow_iso()
        with self._connect() as conn:
            conn.execute(
                '''
                UPDATE sessions
                SET status = ?, updated_at = ?, ended_at = ?
                WHERE runtime_session_id = ? AND ended_at IS NULL
                ''',
                (status, now, now, runtime_session_id),
            )

    def list_sessions(self, include_closed: bool = False) -> list[dict[str, Any]]:
        where = '' if include_closed else 'WHERE s.ended_at IS NULL'
        with self._connect() as conn:
            rows = conn.execute(
                f'''
                SELECT s.*, b.display_name, b.binary_path, b.idb_path, p.name AS project_name
                FROM sessions s
                JOIN binaries b ON b.binary_id = s.binary_id
                JOIN projects p ON p.project_id = s.project_id
                {where}
                ORDER BY s.created_at DESC
                '''
            ).fetchall()
        return [self._row_to_session(row) for row in rows]

    def get_session(self, runtime_session_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                '''
                SELECT s.*, b.display_name, b.binary_path, b.idb_path, p.name AS project_name
                FROM sessions s
                JOIN binaries b ON b.binary_id = s.binary_id
                JOIN projects p ON p.project_id = s.project_id
                WHERE s.runtime_session_id = ?
                ORDER BY s.created_at DESC
                LIMIT 1
                ''',
                (runtime_session_id,),
            ).fetchone()
        return self._row_to_session(row) if row else None

    def _row_to_binary(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            'binary_id': row['binary_id'],
            'project_id': row['project_id'],
            'binary_path': row['binary_path'],
            'display_name': row['display_name'],
            'idb_path': row['idb_path'],
            'created_at': row['created_at'],
            'updated_at': row['updated_at'],
            'metadata': _json_load(row['metadata_json']),
        }

    def _row_to_session(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            'session_row_id': row['session_row_id'],
            'project_id': row['project_id'],
            'project_name': row['project_name'],
            'binary_id': row['binary_id'],
            'binary_name': row['display_name'],
            'binary_path': row['binary_path'],
            'idb_path': row['idb_path'],
            'runtime_session_id': row['runtime_session_id'],
            'worker_port': row['worker_port'],
            'worker_pid': row['worker_pid'],
            'status': row['status'],
            'created_at': row['created_at'],
            'updated_at': row['updated_at'],
            'ended_at': row['ended_at'],
            'metadata': _json_load(row['metadata_json']),
        }

    @staticmethod
    def _guess_idb_path(binary_path: Path) -> Path | None:
        if binary_path.suffix.lower() in {'.i64', '.idb'}:
            return binary_path
        for suffix in ('.i64', '.idb'):
            candidate = binary_path.with_suffix(suffix)
            if candidate.exists():
                return candidate
        return None
