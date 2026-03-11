# xdbg-mcp

基于 `x64dbg_automate` 的 `x64dbg/x32dbg/x96dbg` MCP 服务端。

## 功能概览

- 会话管理：`list/start/connect/disconnect/terminate`。
- 执行控制：`go/pause/step_into/step_over/wait`。
- 寄存器与内存读写。
- 软件断点、硬件断点、内存断点。
- 任意地址反汇编与汇编。
- 瞬时会话故障自动重连与重试。
- 按位数自动选择调试器（`x96dbg` 会根据目标 PE 自动选择 `x32dbg/x64dbg`）。
- 启动增强：插件依赖检查、非 ASCII 目标路径自动复制兜底。

## 完整部署（Windows）

### 1）安装前置依赖

1. 安装 Python `3.11+`。
2. 安装 x64dbg 发行包，确保包含 `x32dbg.exe`、`x64dbg.exe`、`x96dbg.exe`。
3. 确认调试器目录，例如 `D:\tools\x64dbg\release`。

### 2）安装 x64dbg automate 插件文件

将以下文件放到 `<xdbg_release_dir>\plugins\`：

1. `x64dbg-automate.dp32`
2. `x64dbg-automate.dp64`
3. `libzmq-mt-4_3_5.dll`

目录示例：

```text
D:\tools\x64dbg\release\x32dbg.exe
D:\tools\x64dbg\release\x64dbg.exe
D:\tools\x64dbg\release\x96dbg.exe
D:\tools\x64dbg\release\plugins\x64dbg-automate.dp32
D:\tools\x64dbg\release\plugins\x64dbg-automate.dp64
D:\tools\x64dbg\release\plugins\libzmq-mt-4_3_5.dll
```

### 3）安装本 MCP 服务

```powershell
cd xdbg-mcp
python -m pip install -U pip
python -m pip install -e .
```

### 4）启动 MCP 服务

可任选以下命令：

```powershell
set XDBG_PATH=D:\tools\x64dbg\release\x96dbg.exe
xdbg-mcp
```

```powershell
python -m xdbg_mcp --xdbg-path D:\tools\x64dbg\release\x96dbg.exe
```

### 5）MCP 客户端配置示例

将下列配置写入你的 MCP 客户端：

```json
{
  "mcpServers": {
    "xdbg": {
      "command": "python",
      "args": [
        "-m",
        "xdbg_mcp",
        "--xdbg-path",
        "D:\\tools\\x64dbg\\release\\x96dbg.exe"
      ]
    }
  }
}
```

仓库里也提供了示例文件：`mcp.client.json.example`。

### 6）启动后自检

按顺序调用：

1. `health`
2. 调用 `start_session`，参数中传入 `target_exe=<your_challenge.exe>`
3. `debugger_status`
4. 在已知地址调用 `set_breakpoint`，然后执行 `go`

如果 `health.connected=true`，并且 `debugger_status` 返回有效的进程/调试器信息，说明部署完成。

## 稳定性环境变量

- `XDBG_MCP_AUTO_RECONNECT=1|0`  
发生瞬时故障后是否自动重连本地会话。默认：`1`。
- `XDBG_MCP_RETRY_ATTEMPTS=<int>`  
每个工具调用在瞬时故障时的重试次数。默认：`2`。
- `XDBG_MCP_WAIT_POLL_MS=<int>`  
`wait_until_running/stopped` 的轮询间隔（毫秒）。默认：`100`。
- `XDBG_MCP_SKIP_PLUGIN_CHECK=1|0`  
是否跳过 `x64dbg-automate.dp32/.dp64` 与 `libzmq` 的启动检查。默认：`0`。

## 常见启动错误

1. `Missing x64dbg automate plugin dependencies`  
原因：插件文件不在调试器 `plugins` 目录。  
处理：把 `dp32/dp64/libzmq` 复制到报错提示的准确目录。
2. `Failed to load executable`  
原因：目标路径无效、目标位数与调试器不匹配。  
处理：确认 `target_exe` 存在；优先使用 `x96dbg.exe`；尽量避免非 ASCII 路径。
3. `Not connected to x64dbg`  
原因：没有活动会话或会话已失效。  
处理：调用 `start_session` 或 `connect_session`，并检查 `health`。

## CTF 快速流程

用于常见 Reverse 题目的推荐调用顺序：

1. 用 `start_session` 启动题目，传入 `target_exe=<challenge.exe>` 与 `xdbg_path=<x96dbg.exe>`。
2. 用 `set_breakpoint` 在入口、比较分支、关键 API（`memcmp`、`lstrcmp*` 调用点）下断点。
3. 用 `go` + `wait_until_stopped` 跑到关键逻辑位置。
4. 用 `get_register` / `get_registers` 读取分支关键值（例如比较后的 `EAX`）。
5. 用 `read_memory` 抓缓冲区或 key 的中间态，优先拿“程序真实期望值”。
6. 用 `step_over` / `step_into` 收敛路径，逻辑确认后再用 `write_memory_hex` 做最小 patch。

## CTF 指南

- [CTF 逆向实战指南（zh-CN）](docs/CTF_RE_WORKFLOW_zh-CN.md)
