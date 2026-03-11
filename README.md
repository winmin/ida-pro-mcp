# idalib-session-mcp

[中文版](README_zh.md) | English

A session-aware, multi-agent MCP server for headless IDA Pro reverse engineering. Built on top of [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) by [@mrexodia](https://github.com/mrexodia).

## What is this?

This fork extends ida-pro-mcp with `idalib-session-mcp` — a headless MCP server that manages multiple IDA analysis sessions simultaneously. Each binary runs in its own isolated idalib subprocess, and LLM agents can open, switch, and close sessions dynamically.

For the original IDA Pro MCP plugin (GUI mode, tool documentation, prompt engineering tips, etc.), please refer to the **upstream repository**: [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp).

## Key Features

- **Multi-session management**: Open and analyze multiple binaries simultaneously, each in its own idalib subprocess
- **Multi-agent safe**: Every IDA tool has an optional `session_id` parameter — agents can explicitly route calls to specific sessions without relying on global state
- **No cross-contamination**: Agent A switching sessions will not affect Agent B's explicit `session_id` calls
- **62 tools at startup**: AST-based static extraction from IDA API source files provides all tool schemas immediately, before any binary is opened
- **Graceful shutdown**: Ctrl+C cleanly saves all IDBs and terminates child processes

## Architecture

```
┌─────────────────────────────────────────────────────┐
│              idalib-session-mcp                     │
│                                                     │
│   ┌─────────────────────────────────────────────┐   │
│   │  Session Manager (MCP Server)               │   │
│   │  - session_open / close / switch / list     │   │
│   │  - Routes tool calls by session_id          │   │
│   │  - AST-extracted tool schemas (57 IDA tools)│   │
│   └──────┬──────────────┬───────────────────────┘   │
│          │              │                           │
│   ┌──────▼──────┐ ┌─────▼───────┐                   │
│   │ idalib:13400│ │ idalib:13401│  ...               │
│   │ binary_a    │ │ binary_b    │                    │
│   └─────────────┘ └─────────────┘                   │
└─────────────────────────────────────────────────────┘
        ▲                    ▲
        │ session_id=abc     │ session_id=def
   Agent A              Agent B
```

## Prerequisites

- [Python](https://www.python.org/downloads/) **3.11+**
- [IDA Pro](https://hex-rays.com/ida-pro) **9.1+** (**IDA Free is not supported**)
- Set environment variables:
  ```sh
  export IDADIR=/path/to/ida
  ```

## Installation

```sh
pip install https://github.com/WinMin/ida-pro-mcp/archive/refs/heads/main.zip
```

## Usage

### Start the server

```sh
# stdio transport (default, used by most MCP clients)
idalib-session-mcp

# SSE/HTTP transport (for remote/headless use)
idalib-session-mcp --transport http://127.0.0.1:8744/sse
```

### MCP client configuration

**Claude Code / Claude Desktop (stdio):**
```json
{
  "mcpServers": {
    "idalib-session-mcp": {
      "command": "idalib-session-mcp",
      "args": []
    }
  }
}
```

**Claude Code / Claude Desktop (SSE):**
```json
{
  "mcpServers": {
    "idalib-session-mcp": {
      "type": "sse",
      "url": "http://127.0.0.1:8744/sse"
    }
  }
}
```

**From source:**
```json
{
  "mcpServers": {
    "idalib-session-mcp": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/ida-pro-mcp", "idalib-session-mcp"]
    }
  }
}
```

## Session Tools

| Tool | Description |
|------|-------------|
| `session_open(binary_path)` | Open a new analysis session for a binary |
| `session_list()` | List all active sessions |
| `session_switch(session_id)` | Switch the active session |
| `session_close(session_id)` | Close a session (saves IDB) |
| `session_info(session_id?)` | Get session details (defaults to active) |

## Multi-Agent `session_id` Routing

All 57 IDA tools have an injected optional `session_id` parameter. This allows multiple agents to work on different binaries concurrently without interference:

```
Agent A: decompile(addr="0x401000", session_id="abc123")  → routes to binary_a
Agent B: decompile(addr="0x401000", session_id="def456")  → routes to binary_b
```

If `session_id` is omitted, the call falls back to the current active session (set by `session_switch`).

## IDA Tools

All 57 tools from ida-pro-mcp are available. See the [upstream documentation](https://github.com/mrexodia/ida-pro-mcp) for the full tool reference, including:

- Decompilation & disassembly (`decompile`, `disasm`)
- Cross-references & call graphs (`xrefs_to`, `callees`, `callgraph`)
- Function & global listing (`list_funcs`, `list_globals`, `imports`)
- Memory operations (`get_bytes`, `get_int`, `get_string`, `patch`)
- Type operations (`declare_type`, `set_type`, `infer_types`, `read_struct`)
- Rename & comment (`rename`, `set_comments`)
- Pattern search (`find`, `find_bytes`, `find_regex`)
- Debugger (`dbg_start`, `dbg_step_into`, etc. — requires `--unsafe` flag)
- Python execution (`py_eval`)

## Acknowledgments

This project is a fork of [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp). All credit for the core IDA MCP tooling goes to [@mrexodia](https://github.com/mrexodia) and contributors.
