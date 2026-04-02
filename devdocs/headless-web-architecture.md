# Headless Web Architecture

## Goals
- keep upstream `ida_mcp` / `idalib_server` tool surface
- keep pure headless multi-session support
- add persistent `project -> binary -> live session` management
- add a browser UI for strings / decompile / disasm / structs / edits

## Current implementation skeleton
- `src/ida_pro_mcp/session_mcp_server.py`
  - still owns live headless idalib subprocesses
  - now exposes public helpers:
    - `create_session()`
    - `close_session()`
    - `list_session_records()`
    - `call_tool()`
- `src/ida_pro_mcp/headless_project_store.py`
  - SQLite-backed metadata store
  - persists projects, binaries, sessions
  - treats `.i64/.idb` as the durable IDA database artifact
- `src/ida_pro_mcp/headless_web.py`
  - lightweight web manager
  - serves HTML UI + JSON API
  - routes UI actions to upstream MCP tools via live session workers

## Storage model
- SQLite stores metadata/index roots
- IDA `.i64/.idb` remains the source-of-truth analysis database
- next step: add richer materialized indexes for strings/functions/structs/comments

## Implemented API surface
- `GET /api/projects`
- `POST /api/projects`
- `POST /api/projects/{project_id}/binaries`
- `GET /api/sessions`
- `POST /api/binaries/{binary_id}/sessions`
- `POST /api/binaries/{binary_id}/refresh-indexes`
- `GET /api/binaries/{binary_id}/indexes`
- `GET /api/binaries/{binary_id}/functions`
- `GET /api/binaries/{binary_id}/strings`
- `GET /api/binaries/{binary_id}/structs`
- `GET /api/sessions/{id}/lookup`
- `GET /api/sessions/{id}/strings`
- `GET /api/sessions/{id}/decompile`
- `GET /api/sessions/{id}/disasm`
- `GET /api/sessions/{id}/structs`
- `POST /api/sessions/{id}/rename`
- `POST /api/sessions/{id}/comment`

## Next milestones
1. richer struct editing APIs
2. decompile/disasm synchronized navigation model
3. project import/export and session restore
4. auth / RBAC / background job queue
