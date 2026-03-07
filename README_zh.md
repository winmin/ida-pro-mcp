# idalib-session-mcp

中文 | [English](README.md)

基于 [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) 的多会话、多 Agent 无头 IDA Pro MCP 服务器。

## 简介

本项目是 ida-pro-mcp 的 fork，新增了 `idalib-session-mcp` —— 一个无头 MCP 服务器，支持同时管理多个 IDA 分析会话。每个二进制文件在独立的 idalib 子进程中运行，LLM Agent 可以动态地打开、切换和关闭会话。

关于原版 IDA Pro MCP 插件（GUI 模式、工具文档、提示词工程等），请参阅**上游仓库**：[mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)。

## 核心特性

- **多会话管理**：同时打开和分析多个二进制文件，每个文件在独立的 idalib 子进程中运行
- **多 Agent 安全**：每个 IDA 工具都有可选的 `session_id` 参数，Agent 可以显式指定目标会话，不依赖全局状态
- **无交叉污染**：Agent A 切换会话不会影响 Agent B 的显式 `session_id` 调用
- **启动即可用 62 个工具**：基于 AST 静态解析 IDA API 源码，启动时即提供全部工具 schema，无需先打开二进制文件
- **优雅退出**：Ctrl+C 会保存所有 IDB 并终止子进程

## 架构

```
┌─────────────────────────────────────────────────────┐
│              idalib-session-mcp                     │
│                                                     │
│   ┌─────────────────────────────────────────────┐   │
│   │  会话管理器 (MCP Server)                     │   │
│   │  - session_open / close / switch / list     │   │
│   │  - 根据 session_id 路由工具调用              │   │
│   │  - AST 提取的工具 schema (57 个 IDA 工具)    │   │
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

## 前置条件

- [Python](https://www.python.org/downloads/) **3.11+**
- [IDA Pro](https://hex-rays.com/ida-pro) **9.1+** 并安装 [idalib](https://docs.hex-rays.com/user-guide/idalib)（**不支持 IDA Free**）
- 设置环境变量：
  ```sh
  export IDALIB_PATH=/path/to/ida/idalib
  export IDAPRO_PATH=/path/to/ida
  ```

## 安装

```sh
pip install https://github.com/WinMin/ida-pro-mcp/archive/refs/heads/main.zip
```

## 使用

### 启动服务器

```sh
# stdio 传输（默认，大多数 MCP 客户端使用）
idalib-session-mcp

# SSE/HTTP 传输（远程/无头场景）
idalib-session-mcp --transport http://127.0.0.1:8744/sse
```

### MCP 客户端配置

**Claude Code / Claude Desktop (stdio)：**
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

**Claude Code / Claude Desktop (SSE)：**
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

**从源码运行：**
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

## 会话工具

| 工具 | 说明 |
|------|------|
| `session_open(binary_path)` | 打开一个新的分析会话 |
| `session_list()` | 列出所有活跃会话 |
| `session_switch(session_id)` | 切换当前活跃会话 |
| `session_close(session_id)` | 关闭会话（保存 IDB） |
| `session_info(session_id?)` | 获取会话详情（默认为当前活跃会话） |

## 多 Agent `session_id` 路由

所有 57 个 IDA 工具都注入了可选的 `session_id` 参数，支持多 Agent 并发操作不同二进制文件：

```
Agent A: decompile(addr="0x401000", session_id="abc123")  → 路由到 binary_a
Agent B: decompile(addr="0x401000", session_id="def456")  → 路由到 binary_b
```

如果省略 `session_id`，调用将回退到当前活跃会话（由 `session_switch` 设置）。

## IDA 工具

完整继承 ida-pro-mcp 的 57 个工具。详细文档请参阅[上游仓库](https://github.com/mrexodia/ida-pro-mcp)，包括：

- 反编译与反汇编（`decompile`、`disasm`）
- 交叉引用与调用图（`xrefs_to`、`callees`、`callgraph`）
- 函数与全局变量列表（`list_funcs`、`list_globals`、`imports`）
- 内存操作（`get_bytes`、`get_int`、`get_string`、`patch`）
- 类型操作（`declare_type`、`set_type`、`infer_types`、`read_struct`）
- 重命名与注释（`rename`、`set_comments`）
- 模式搜索（`find`、`find_bytes`、`find_regex`）
- 调试器（`dbg_start`、`dbg_step_into` 等 —— 需要 `--unsafe` 参数）
- Python 执行（`py_eval`）

## 致谢

本项目 fork 自 [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)，核心 IDA MCP 工具的功劳归于 [@mrexodia](https://github.com/mrexodia) 及贡献者。
