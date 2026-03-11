# xdbg MCP CTF 逆向实战指南（zh-CN）

> 适用对象：用 `x64dbg/x32dbg + xdbg MCP` 做 CTF Reverse 辅助调试的选手。  
> 目标：提高做题效率、减少卡顿、形成可复用流程。

## 1. 适用题型

本指南适用于：

1. Windows Reverse（PE 程序、GUI CrackMe、命令行校验题）。
2. 动态分析辅助静态逆向（字符串混淆、分支校验、内存生成 key）。


## 2. 环境建议

1. `x64dbg`（含 `x32dbg/x64dbg/x96dbg`）。
2. `x64dbg-automate` 插件（`dp32/dp64 + libzmq`）。
3. `Python 3.11+`。
4. `xdbg-mcp`。

部署建议：

1. 插件文件必须落到“你实际使用的 xdbg 可执行文件同级目录下的 `plugins`”。
2. 只安装 Python 包不够，`dp32/dp64/libzmq` 仍需手动复制。
3. 插件下载建议直接使用官方 Releases：`https://github.com/dariushoule/x64dbg-automate/releases`。
4. 完整搭建步骤请先按 README 的“完整部署（Windows）”执行，再做本指南中的题目流程。

## 3. 快速启动

```powershell
python -m xdbg_mcp --xdbg-path <X64DBG_DIR>\x96dbg.exe
```

首次连通建议调用顺序：

1. `health`
2. `start_session`（或 `list_sessions` + `connect_session`）
3. `debugger_status`
4. `run_to`（关键地址）+ `snapshot_context`

## 4. CTF 标准做题流程（SOP）

### 4.1 赛前准备

1. 先做静态浏览：导入表、字符串、可疑常量。
2. 明确目标：找正确输入、过校验、还原算法，还是做 patch。

### 4.2 动态调试

1. 在入口、按钮分发、比较函数（如 `lstrcmp/memcmp`）下断点。
2. 用 `step_over` 快速穿过系统库，关键点再 `step_into`。
3. 用 `read_memory/get_register(s)` 抓中间值。
4. 在循环生成逻辑里读缓冲区，优先拿“程序真实期望值”。

### 4.3 收敛答案

1. 用断点验证比较返回值（例如 `EAX==0`）。
2. 再验证是否走成功分支（比如跳转到 success block）。
3. 最后再手动输入确认 UI 提示一致。

## 5. xdbg MCP 高效用法

推荐高频工具：

1. 会话：`start_session` / `connect_session` / `terminate_session`
2. 控制：`run_to` / `go` / `pause` / `step_over` / `wait_until_stopped`
3. 观察：`get_register` / `get_registers` / `read_memory` / `disassemble`
4. 快照：`snapshot_context`（寄存器 + 当前指令 + 栈）
5. 断点：`set_breakpoint` / `list_breakpoints` / `clear_breakpoint`
6. 修改：`write_memory_hex` / `set_register`

实战建议：

1. 异常密集区别长时间 `go`，优先短跑 + 单步。
2. `wait_until_*` 超时后先看 `health`，再做重连，不要盲目重复下断点。
3. 题目路径尽量 ASCII，减少路径编码问题。

## 6. 常见问题与处理

### Q1: `start_session` 失败

排查顺序：

1. 位数是否匹配（32 位题目优先 `x32dbg`）。
2. 插件是否齐全（`x64dbg-automate.dp32/.dp64 + libzmq`）。
3. 路径是否存在、是否可读。

### Q2: `go/wait` 经常超时

1. 使用短周期断点推进，不要无限运行。
2. 优先 `step_over` 穿系统函数。
3. 必要时 `disconnect -> connect_session` 恢复会话。

### Q3: `command` 返回 `executed=false`

1. 某些命令在当前状态不可执行是正常现象。
2. 优先使用结构化工具（`set_breakpoint/read_memory/...`），少依赖 raw command。

## 7. 比赛中可复用模板

建议仓库里固定这几类模板：

1. `docs/CTF_RE_WORKFLOW_zh-CN.md`（本文件）
2. `docs/CTF_WRITEUP_TEMPLATE.md`
3. `scripts/patch_template.py`（自动改跳转/改比较）
4. `scripts/keygen_template.py`（按中间值生成答案）

## 8. 合规声明

1. 仅用于 CTF、授权练习与教学研究。
2. 不用于未授权目标。
