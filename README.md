# IDA Pro MCP

[中文版](README_zh.md) | English

MCP Server for IDA Pro reverse engineering. Fork of [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) with multi-binary pool proxy and infrastructure improvements.

## What's different from upstream?

This fork adds:

- **`idalib-pool`** — a proxy server that manages a pool of idalib instances for concurrent multi-binary analysis
- **Unix domain socket** support for idalib server (avoids TCP port conflicts)
- **`execute_sync` deadlock fix** for headless idalib mode
- **Bearer token authentication** (`--auth-token` / `IDA_MCP_AUTH_TOKEN`)
- **stdio / HTTP / SSE transport** for the pool proxy

For the original IDA Pro MCP plugin (GUI mode, tool documentation, prompt engineering, etc.), see the upstream: [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp).

## Three ways to run

| Mode | Command | Use case |
|------|---------|----------|
| **GUI plugin** | `ida-pro-mcp` | Connecting to IDA Pro with GUI open |
| **Headless single** | `idalib-mcp [binary]` | Analyzing one binary without GUI |
| **Headless pool** | `idalib-pool [binary]` | Analyzing multiple binaries concurrently |

## idalib-pool: Multi-Binary Analysis

The pool proxy manages multiple idalib instances behind a single MCP endpoint. Each instance holds one active IDB — no in-process switching overhead.

```
MCP Client
    │
    ▼  stdio / HTTP :8750
┌───────────────────────────┐
│  idalib-pool (proxy)       │
│  routes by session_id      │
└───┬───────────┬────────────┘
    │           │
  unix sock   unix sock
    ▼           ▼
┌─────────┐ ┌─────────┐
│ idalib#0 │ │ idalib#1 │
│ httpd    │ │ libcrypto│
└─────────┘ └─────────┘
```

### Key features

- **1 instance = 1 session**: no IDB switching, no thrashing
- **Optional `session_id`** on every IDA tool: omit for default session, specify for explicit routing. Parallel calls to different sessions are safe.
- **`idalib_switch`** only changes the default session pointer — zero IDB cost
- **LRU eviction** when pool is full (`--max-instances N`)
- **Unlimited mode** (`--max-instances 0`): fresh instance per open, destroy on close
- **Path dedup**: re-opening the same binary returns the existing session

### Usage

```sh
# stdio (default, for MCP clients like Claude Desktop)
idalib-pool

# stdio with initial binary
idalib-pool /path/to/binary

# HTTP/SSE mode
idalib-pool --transport http://127.0.0.1:8750

# Multi-instance pool
idalib-pool --max-instances 3

# With authentication
idalib-pool --auth-token mysecret
# or: IDA_MCP_AUTH_TOKEN=mysecret idalib-pool
```

### Workflow example

```
idalib_open("/firmware/httpd")        → session "httpd-01" (default)
idalib_open("/firmware/libcrypto.so") → session "crypto-01"

# Explicit routing — parallel safe
decompile("main", session_id="httpd-01")
decompile("SSL_connect", session_id="crypto-01")

# Or switch default and omit session_id
idalib_switch("crypto-01")
decompile("SSL_connect")  → routes to crypto-01
```

## Prerequisites

- [Python](https://www.python.org/downloads/) **3.11+**
- [IDA Pro](https://hex-rays.com/ida-pro) **8.3+** (9.0+ recommended) with [idalib](https://docs.hex-rays.com/user-guide/idalib) — **IDA Free is not supported**
- Set `IDADIR` to your IDA installation path

## Installation

```sh
pip install https://github.com/zh-explorer/ida-pro-mcp/archive/refs/heads/dev.zip
```

Or from source:
```sh
git clone https://github.com/zh-explorer/ida-pro-mcp
cd ida-pro-mcp
uv run idalib-pool
```

## MCP Client Configuration

**Claude Code / Claude Desktop (stdio, recommended):**
```json
{
  "mcpServers": {
    "ida-pro-mcp": {
      "command": "idalib-pool"
    }
  }
}
```

**HTTP/SSE mode:**
```json
{
  "mcpServers": {
    "ida-pro-mcp": {
      "url": "http://127.0.0.1:8750/mcp"
    }
  }
}
```

**From source with uv:**
```json
{
  "mcpServers": {
    "ida-pro-mcp": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/ida-pro-mcp", "idalib-pool"]
    }
  }
}
```

## Session Management Tools

| Tool | Description |
|------|-------------|
| `idalib_open(path, session_id?)` | Open a binary, auto-assign to an instance |
| `idalib_close(session_id)` | Close a session (saves IDB) |
| `idalib_switch(session_id)` | Set the default session (no IDB cost) |
| `idalib_list()` | List all sessions |
| `idalib_current()` | Get the default session info |
| `idalib_save(path?)` | Save the active IDB |

## IDA Tools

66 tools from upstream ida-pro-mcp, all with optional `session_id` routing. See the [upstream documentation](https://github.com/mrexodia/ida-pro-mcp) for details:

- Decompilation & disassembly (`decompile`, `disasm`)
- Cross-references & call graphs (`xrefs_to`, `callees`, `callgraph`)
- Function & global listing (`list_funcs`, `list_globals`, `imports`)
- Memory operations (`get_bytes`, `get_int`, `get_string`, `patch`)
- Type operations (`declare_type`, `set_type`, `infer_types`, `read_struct`)
- Rename & comment (`rename`, `set_comments`)
- Pattern search (`find`, `find_bytes`, `find_regex`)
- Binary survey (`survey_binary` — start here for triage)
- Python execution (`py_eval`)

## Acknowledgments

Fork of [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) by [@mrexodia](https://github.com/mrexodia). Multi-binary pool proxy developed with [@WinMin](https://github.com/WinMin).
