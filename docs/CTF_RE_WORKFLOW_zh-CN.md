# xdbg-mcp CTF 逆向实战指南（中文）

本文给出一套针对 CTF Reverse 的高效流程，默认你已完成 README 中的部署。

## 1. 目标

1. 快速定位校验路径
2. 减少卡在输入/反调试/会话断连上的时间
3. 形成可复用操作模板

## 2. 推荐流程（SOP）

### Step 1：启动与自检

1. `health`
2. `start_session(target_exe=..., xdbg_path=...x96dbg.exe)`
3. `debugger_status`

### Step 2：跑到关键点

优先用：

- `run_to`
- `set_breakpoint + go + wait_until_stopped(detailed=true)`

`wait_until_stopped(detailed=true)` 的重点字段：

- `matched`
- `timed_out`
- `stop_reason`
- `stop_event`
- `instruction_pointer`

### Step 3：抓上下文

1. `snapshot_context`
2. `read_memory`
3. `get_register(s)`

### Step 4：细化执行

- `step_over`：快速跨系统调用
- `step_into`：进入关键算法
- `step_trace`：批量单步并观察寄存器变化

### Step 5：验证假设

- 用 `run_until_expr` 跑到目标条件
- 用 `find_memory_pattern` 找关键常量/标记串
- 必要时 `write_memory_hex` 做最小实验性 patch

## 3. 输入阻塞（scanf/read/fgets）处理

如果程序在输入点卡住，不要盲目 `go`。

推荐工具：`inject_string_and_continue`

参数语义：

- `buffer_address`：输入缓冲区地址（可写表达式，如 `ebp-0x96`）
- `text`：你要注入的候选输入
- `continue_at`：跳过输入调用后的地址
- `encoding`：`ascii` / `utf-8` / `utf-16le`
- `append_null`：是否补零结尾

典型链路：

1. 停在输入调用附近
2. `inject_string_and_continue`
3. `run_to` 到比较分支
4. `snapshot_context` 验证比较结果

## 4. 断连与恢复策略

本项目已支持自动重连并恢复 MCP 下发的断点。

建议：

1. 出现瞬时异常先看 `health`
2. 关注 `reconnect_count`
3. 如确实错乱，`disconnect` 后 `connect_session`

## 5. 事件队列调试

新增工具：

1. `get_latest_event`
2. `drain_events`
3. `wait_for_event`

用途：

- 明确到底是 `breakpoint`、`exception` 还是 `pause`
- 解决“为什么停下/为什么没停到预期地址”

## 6. 常见失误

1. 只看 `run_to` 返回，不看 `instruction_pointer`
2. 命中其他断点却误判“到目标”
3. 输入阻塞时长时间 `go`，导致超时
4. 没有记录每次关键断点的寄存器和内存

## 7. 一段最小实战模板

1. `start_session`
2. `run_to(入口)`
3. `set_breakpoint(比较点)`
4. `go`
5. `wait_until_stopped(detailed=true)`
6. `snapshot_context`
7. 必要时 `inject_string_and_continue`
8. 重复 4~7，直到收敛出 flag
