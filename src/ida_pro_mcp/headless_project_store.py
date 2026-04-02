from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_load(blob: str | None) -> Any:
    if not blob:
        return {}
    try:
        return json.loads(blob)
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

                CREATE TABLE IF NOT EXISTS function_index (
                    binary_id TEXT NOT NULL,
                    addr TEXT NOT NULL,
                    name TEXT NOT NULL,
                    size TEXT,
                    raw_json TEXT NOT NULL,
                    refreshed_at TEXT NOT NULL,
                    PRIMARY KEY(binary_id, addr),
                    FOREIGN KEY(binary_id) REFERENCES binaries(binary_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS string_index (
                    binary_id TEXT NOT NULL,
                    addr TEXT NOT NULL,
                    value TEXT NOT NULL,
                    raw_json TEXT NOT NULL,
                    refreshed_at TEXT NOT NULL,
                    PRIMARY KEY(binary_id, addr, value),
                    FOREIGN KEY(binary_id) REFERENCES binaries(binary_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS struct_index (
                    binary_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    ordinal INTEGER,
                    size INTEGER,
                    cardinality INTEGER,
                    is_union INTEGER,
                    raw_json TEXT NOT NULL,
                    refreshed_at TEXT NOT NULL,
                    PRIMARY KEY(binary_id, name),
                    FOREIGN KEY(binary_id) REFERENCES binaries(binary_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS binary_index_state (
                    binary_id TEXT PRIMARY KEY,
                    functions_refreshed_at TEXT,
                    strings_refreshed_at TEXT,
                    structs_refreshed_at TEXT,
                    FOREIGN KEY(binary_id) REFERENCES binaries(binary_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS operation_history (
                    operation_id TEXT PRIMARY KEY,
                    project_id TEXT,
                    binary_id TEXT,
                    runtime_session_id TEXT,
                    operation_type TEXT NOT NULL,
                    target TEXT,
                    payload_json TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(project_id) REFERENCES projects(project_id) ON DELETE SET NULL,
                    FOREIGN KEY(binary_id) REFERENCES binaries(binary_id) ON DELETE SET NULL
                );

                CREATE INDEX IF NOT EXISTS idx_operation_history_binary_id
                ON operation_history(binary_id, created_at DESC);

                CREATE INDEX IF NOT EXISTS idx_operation_history_session_id
                ON operation_history(runtime_session_id, created_at DESC);
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

    def list_sessions_for_binary(
        self, binary_id: str, include_closed: bool = False
    ) -> list[dict[str, Any]]:
        where = "" if include_closed else "AND s.ended_at IS NULL"
        with self._connect() as conn:
            rows = conn.execute(
                f'''
                SELECT s.*, b.display_name, b.binary_path, b.idb_path, p.name AS project_name
                FROM sessions s
                JOIN binaries b ON b.binary_id = s.binary_id
                JOIN projects p ON p.project_id = s.project_id
                WHERE s.binary_id = ?
                {where}
                ORDER BY s.created_at DESC
                ''',
                (binary_id,),
            ).fetchall()
        return [self._row_to_session(row) for row in rows]

    def get_live_session_for_binary(self, binary_id: str) -> dict[str, Any] | None:
        sessions = self.list_sessions_for_binary(binary_id, include_closed=False)
        return sessions[0] if sessions else None

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

    def record_operation(
        self,
        operation_type: str,
        payload: dict[str, Any] | list[Any] | None,
        result: dict[str, Any] | list[Any] | None,
        *,
        project_id: str | None = None,
        binary_id: str | None = None,
        runtime_session_id: str | None = None,
        target: str | None = None,
    ) -> dict[str, Any]:
        operation_id = uuid.uuid4().hex[:16]
        created_at = utcnow_iso()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO operation_history(
                    operation_id, project_id, binary_id, runtime_session_id,
                    operation_type, target, payload_json, result_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    operation_id,
                    project_id,
                    binary_id,
                    runtime_session_id,
                    operation_type,
                    target,
                    json.dumps(payload or {}),
                    json.dumps(result or {}),
                    created_at,
                ),
            )
        return self.get_operation(operation_id) or {
            "operation_id": operation_id,
            "created_at": created_at,
        }

    def list_operations(
        self,
        *,
        project_id: str | None = None,
        binary_id: str | None = None,
        runtime_session_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        clauses = []
        params: list[Any] = []
        if project_id:
            clauses.append("project_id = ?")
            params.append(project_id)
        if binary_id:
            clauses.append("binary_id = ?")
            params.append(binary_id)
        if runtime_session_id:
            clauses.append("runtime_session_id = ?")
            params.append(runtime_session_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT * FROM operation_history
                {where}
                ORDER BY created_at DESC
                LIMIT ?
                """,
                params,
            ).fetchall()
        return [self._row_to_operation(row) for row in rows]

    def get_operation(self, operation_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM operation_history WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()
        return self._row_to_operation(row) if row else None

    def replace_function_index(self, binary_id: str, items: list[dict[str, Any]]) -> None:
        refreshed_at = utcnow_iso()
        with self._connect() as conn:
            conn.execute("DELETE FROM function_index WHERE binary_id = ?", (binary_id,))
            conn.executemany(
                """
                INSERT INTO function_index(binary_id, addr, name, size, raw_json, refreshed_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        binary_id,
                        str(item.get("addr", "")),
                        str(item.get("name", "")),
                        None if item.get("size") is None else str(item.get("size")),
                        json.dumps(item),
                        refreshed_at,
                    )
                    for item in items
                ],
            )
            conn.execute(
                """
                INSERT INTO binary_index_state(binary_id, functions_refreshed_at)
                VALUES (?, ?)
                ON CONFLICT(binary_id) DO UPDATE SET functions_refreshed_at=excluded.functions_refreshed_at
                """,
                (binary_id, refreshed_at),
            )

    def replace_string_index(self, binary_id: str, items: list[dict[str, Any]]) -> None:
        refreshed_at = utcnow_iso()
        with self._connect() as conn:
            conn.execute("DELETE FROM string_index WHERE binary_id = ?", (binary_id,))
            conn.executemany(
                """
                INSERT INTO string_index(binary_id, addr, value, raw_json, refreshed_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (
                        binary_id,
                        str(item.get("addr", "")),
                        str(
                            item.get("string")
                            or item.get("value")
                            or item.get("text")
                            or ""
                        ),
                        json.dumps(item),
                        refreshed_at,
                    )
                    for item in items
                ],
            )
            conn.execute(
                """
                INSERT INTO binary_index_state(binary_id, strings_refreshed_at)
                VALUES (?, ?)
                ON CONFLICT(binary_id) DO UPDATE SET strings_refreshed_at=excluded.strings_refreshed_at
                """,
                (binary_id, refreshed_at),
            )

    def replace_struct_index(self, binary_id: str, items: list[dict[str, Any]]) -> None:
        refreshed_at = utcnow_iso()
        with self._connect() as conn:
            conn.execute("DELETE FROM struct_index WHERE binary_id = ?", (binary_id,))
            conn.executemany(
                """
                INSERT INTO struct_index(
                    binary_id, name, ordinal, size, cardinality, is_union, raw_json, refreshed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        binary_id,
                        str(item.get("name", "")),
                        item.get("ordinal"),
                        item.get("size"),
                        item.get("cardinality"),
                        1 if item.get("is_union") else 0,
                        json.dumps(item),
                        refreshed_at,
                    )
                    for item in items
                ],
            )
            conn.execute(
                """
                INSERT INTO binary_index_state(binary_id, structs_refreshed_at)
                VALUES (?, ?)
                ON CONFLICT(binary_id) DO UPDATE SET structs_refreshed_at=excluded.structs_refreshed_at
                """,
                (binary_id, refreshed_at),
            )

    def get_binary_index_state(self, binary_id: str) -> dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM binary_index_state WHERE binary_id = ?", (binary_id,)
            ).fetchone()
        return (
            {
                "binary_id": row["binary_id"],
                "functions_refreshed_at": row["functions_refreshed_at"],
                "strings_refreshed_at": row["strings_refreshed_at"],
                "structs_refreshed_at": row["structs_refreshed_at"],
            }
            if row
            else {
                "binary_id": binary_id,
                "functions_refreshed_at": None,
                "strings_refreshed_at": None,
                "structs_refreshed_at": None,
            }
        )

    def list_function_index(
        self, binary_id: str, filter_text: str = "", limit: int = 200, offset: int = 0
    ) -> list[dict[str, Any]]:
        pattern = f"%{filter_text.lower()}%"
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM function_index
                WHERE binary_id = ? AND lower(name) LIKE ?
                ORDER BY addr
                LIMIT ? OFFSET ?
                """,
                (binary_id, pattern, limit, offset),
            ).fetchall()
        return [json.loads(row["raw_json"]) for row in rows]

    def list_string_index(
        self, binary_id: str, filter_text: str = "", limit: int = 200, offset: int = 0
    ) -> list[dict[str, Any]]:
        pattern = f"%{filter_text.lower()}%"
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM string_index
                WHERE binary_id = ? AND lower(value) LIKE ?
                ORDER BY addr
                LIMIT ? OFFSET ?
                """,
                (binary_id, pattern, limit, offset),
            ).fetchall()
        return [json.loads(row["raw_json"]) for row in rows]

    def list_struct_index(
        self, binary_id: str, filter_text: str = "", limit: int = 200, offset: int = 0
    ) -> list[dict[str, Any]]:
        pattern = f"%{filter_text.lower()}%"
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM struct_index
                WHERE binary_id = ? AND lower(name) LIKE ?
                ORDER BY name
                LIMIT ? OFFSET ?
                """,
                (binary_id, pattern, limit, offset),
            ).fetchall()
        return [json.loads(row["raw_json"]) for row in rows]

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

    def _row_to_operation(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "operation_id": row["operation_id"],
            "project_id": row["project_id"],
            "binary_id": row["binary_id"],
            "runtime_session_id": row["runtime_session_id"],
            "operation_type": row["operation_type"],
            "target": row["target"],
            "payload": _json_load(row["payload_json"]),
            "result": _json_load(row["result_json"]),
            "created_at": row["created_at"],
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
