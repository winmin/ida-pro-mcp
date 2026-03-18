# IDA Pro MCP

中文 | [English](README.md)

IDA Pro 逆向工程 MCP 服务器。基于 [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) 的 fork，新增多 binary 池代理和基础设施改进。

## 与上游的区别

本 fork 新增了：

- **`idalib-pool`** — 代理服务器，管理多个 idalib 实例，支持多 binary 并发分析
- **Unix domain socket** 支持（避免 TCP 端口冲突）
- **`execute_sync` 死锁修复**（headless idalib 模式）
- **Bearer token 认证**（`--auth-token` / `IDA_MCP_AUTH_TOKEN`）
- **stdio / HTTP / SSE 传输** 支持

原版 IDA Pro MCP 插件（GUI 模式、工具文档、提示词工程等）请参阅上游：[mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)。

## 三种运行方式

| 模式 | 命令 | 适用场景 |
|------|------|----------|
| **GUI 插件** | `ida-pro-mcp` | 连接已打开 GUI 的 IDA Pro |
| **无头单 binary** | `idalib-mcp [binary]` | 不需要 GUI 分析单个 binary |
| **无头池模式** | `idalib-pool [binary]` | 并发分析多个 binary |

## idalib-pool：多 Binary 分析

池代理在单个 MCP 端点后面管理多个 idalib 实例。每个实例持有一个活跃 IDB——无进程内切换开销。

```
MCP 客户端
    │
    ▼  stdio / HTTP :8750
┌───────────────────────────┐
│  idalib-pool (代理)        │
│  按 session_id 路由        │
└───┬───────────┬────────────┘
    │           │
  unix sock   unix sock
    ▼           ▼
┌─────────┐ ┌─────────┐
│ idalib#0 │ │ idalib#1 │
│ httpd    │ │ libcrypto│
└─────────┘ └─────────┘
```

### 核心特性

- **1 实例 = 1 会话**：无 IDB 切换，无抖动
- **可选 `session_id`**：所有 IDA 工具都支持。省略则用默认会话，指定则路由到目标会话。并行调用不同会话是安全的。
- **`idalib_switch`** 只修改默认会话指针——零 IDB 开销
- **LRU 淘汰**：池满时自动淘汰最久未用的会话（`--max-instances N`）
- **无限模式**（`--max-instances 0`）：每次 open 启动新实例，close 时销毁
- **路径去重**：重复打开同一 binary 返回已有会话

### 使用方法

```sh
# stdio（默认，适用于 Claude Desktop 等 MCP 客户端）
idalib-pool

# stdio 并加载初始 binary
idalib-pool /path/to/binary

# HTTP/SSE 模式
idalib-pool --transport http://127.0.0.1:8750

# 多实例池
idalib-pool --max-instances 3

# 带认证
idalib-pool --auth-token mysecret
# 或：IDA_MCP_AUTH_TOKEN=mysecret idalib-pool
```

### 工作流示例

```
idalib_open("/firmware/httpd")        → 会话 "httpd-01"（默认）
idalib_open("/firmware/libcrypto.so") → 会话 "crypto-01"

# 显式路由——并行安全
decompile("main", session_id="httpd-01")
decompile("SSL_connect", session_id="crypto-01")

# 或切换默认后省略 session_id
idalib_switch("crypto-01")
decompile("SSL_connect")  → 路由到 crypto-01
```

## 前置条件

- [Python](https://www.python.org/downloads/) **3.11+**
- [IDA Pro](https://hex-rays.com/ida-pro) **8.3+**（推荐 9.0+）并安装 [idalib](https://docs.hex-rays.com/user-guide/idalib) —— **不支持 IDA Free**
- 设置 `IDADIR` 为 IDA 安装路径

## 安装

```sh
pip install https://github.com/zh-explorer/ida-pro-mcp/archive/refs/heads/dev.zip
```

或从源码：
```sh
git clone https://github.com/zh-explorer/ida-pro-mcp
cd ida-pro-mcp
uv run idalib-pool
```

## MCP 客户端配置

**Claude Code / Claude Desktop（stdio，推荐）：**
```json
{
  "mcpServers": {
    "ida-pro-mcp": {
      "command": "idalib-pool"
    }
  }
}
```

**HTTP/SSE 模式：**
```json
{
  "mcpServers": {
    "ida-pro-mcp": {
      "url": "http://127.0.0.1:8750/mcp"
    }
  }
}
```

**从源码用 uv 运行：**
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

## 会话管理工具

| 工具 | 说明 |
|------|------|
| `idalib_open(path, session_id?)` | 打开 binary，自动分配实例 |
| `idalib_close(session_id)` | 关闭会话（保存 IDB） |
| `idalib_switch(session_id)` | 设置默认会话（无 IDB 开销） |
| `idalib_list()` | 列出所有会话 |
| `idalib_current()` | 获取默认会话信息 |
| `idalib_save(path?)` | 保存当前 IDB |

## IDA 工具

继承上游 ida-pro-mcp 的 66 个工具，全部支持可选 `session_id` 路由。详细文档参阅[上游仓库](https://github.com/mrexodia/ida-pro-mcp)：

- 反编译与反汇编（`decompile`、`disasm`）
- 交叉引用与调用图（`xrefs_to`、`callees`、`callgraph`）
- 函数与全局变量列表（`list_funcs`、`list_globals`、`imports`）
- 内存操作（`get_bytes`、`get_int`、`get_string`、`patch`）
- 类型操作（`declare_type`、`set_type`、`infer_types`、`read_struct`）
- 重命名与注释（`rename`、`set_comments`）
- 模式搜索（`find`、`find_bytes`、`find_regex`）
- Binary 概览（`survey_binary` —— 建议作为分析第一步）
- Python 执行（`py_eval`）

## 致谢

Fork 自 [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)，由 [@mrexodia](https://github.com/mrexodia) 开发。多 binary 池代理由 [@zh-explorer](https://github.com/zh-explorer) 和 [@WinMin](https://github.com/WinMin) 合作开发。
