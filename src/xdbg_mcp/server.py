from __future__ import annotations

import argparse
import dataclasses
import enum
import os
import shutil
import struct
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, TypeVar

from mcp.server.fastmcp import FastMCP
from x64dbg_automate import X64DbgClient
from x64dbg_automate.models import (
    BreakpointType,
    HardwareBreakpointType,
    MemoryBreakpointType,
    StandardBreakpointType,
)

MAX_MEMORY_RW = 0x10000
TRANSIENT_ERROR_MARKERS = (
    "timed out",
    "deadline has elapsed",
    "resource temporarily unavailable",
    "operation cannot be accomplished in current state",
    "not connected to x64dbg",
    "session did not appear in a reasonable amount of time",
)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in ("0", "false", "no", "off")


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return max(minimum, int(raw))
    except ValueError:
        return default


@dataclass
class ServerState:
    client: X64DbgClient | None = None
    xdbg_path: str = os.environ.get("XDBG_PATH", "x64dbg")
    resolved_xdbg_path: str = ""
    resolved_plugin_dir: str = ""
    last_session_pid: int | None = None
    auto_reconnect: bool = _env_bool("XDBG_MCP_AUTO_RECONNECT", True)
    retry_attempts: int = _env_int("XDBG_MCP_RETRY_ATTEMPTS", 2)
    wait_poll_ms: int = _env_int("XDBG_MCP_WAIT_POLL_MS", 100)
    skip_plugin_check: bool = _env_bool("XDBG_MCP_SKIP_PLUGIN_CHECK", False)


STATE = ServerState()

mcp = FastMCP(
    "xdbg",
    instructions=(
        "MCP server for x64dbg/x32dbg/x96dbg via x64dbg_automate. "
        "Use list_sessions + connect_session, or start_session first. "
        "Address/value parameters accept decimal or hex (0x...) format. "
        "For expression parsing (RIP/rsp+0x20/symbol), keep a debugger connection active."
    ),
)


def _to_jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, enum.Enum):
        return value.value
    if dataclasses.is_dataclass(value):
        return {k: _to_jsonable(v) for k, v in dataclasses.asdict(value).items()}
    if hasattr(value, "model_dump") and callable(value.model_dump):
        return _to_jsonable(value.model_dump())
    if isinstance(value, dict):
        return {str(k): _to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_to_jsonable(v) for v in value]
    if hasattr(value, "__dict__"):
        return {k: _to_jsonable(v) for k, v in vars(value).items()}
    return str(value)


T = TypeVar("T")


def _ok(result: Any = None) -> dict[str, Any]:
    return {"ok": True, "result": _to_jsonable(result)}


def _error(exc: Exception) -> dict[str, Any]:
    message = str(exc)
    lower = message.lower()
    hint = ""
    if "failed to load executable" in lower:
        hint = "Check target path/bitness, and prefer ASCII target paths."
    elif "not connected to x64dbg" in lower:
        hint = "Use start_session/connect_session; auto-reconnect may recover stale sessions."
    elif "session_pid is required" in lower:
        hint = "Call list_sessions and pass session_pid explicitly."
    payload = {"ok": False, "error": message}
    if hint:
        payload["hint"] = hint
    return payload


def _session_pid_of(client: X64DbgClient | None) -> int | None:
    if client is None:
        return None
    value = getattr(client, "session_pid", None)
    return value if isinstance(value, int) and value > 0 else None


def _set_client(client: X64DbgClient, resolved_path: str) -> None:
    STATE.client = client
    STATE.resolved_xdbg_path = resolved_path
    session_pid = _session_pid_of(client)
    if session_pid is not None:
        STATE.last_session_pid = session_pid


def _clear_client() -> None:
    STATE.client = None


def _is_client_alive(client: X64DbgClient | None) -> bool:
    if client is None:
        return False
    try:
        client.get_debugger_pid()
        return True
    except Exception:
        return False


def _is_transient_error(exc: Exception) -> bool:
    text = str(exc).lower()
    return any(marker in text for marker in TRANSIENT_ERROR_MARKERS)


def _reconnect_client() -> bool:
    if not STATE.auto_reconnect:
        return False

    path_hint = STATE.resolved_xdbg_path or STATE.xdbg_path
    try:
        resolved = _resolve_debugger_path(path_hint)
    except Exception:
        resolved = path_hint

    try:
        sessions = X64DbgClient.list_sessions()
    except Exception:
        return False
    if not sessions:
        return False

    chosen_pid: int | None = None
    if STATE.last_session_pid is not None:
        for session in sessions:
            if session.pid == STATE.last_session_pid:
                chosen_pid = session.pid
                break

    if chosen_pid is None:
        current_pid = _session_pid_of(STATE.client)
        if current_pid is not None:
            for session in sessions:
                if session.pid == current_pid:
                    chosen_pid = session.pid
                    break

    if chosen_pid is None and len(sessions) == 1:
        chosen_pid = sessions[0].pid

    if chosen_pid is None:
        return False

    try:
        client = X64DbgClient(resolved)
        client.attach_session(chosen_pid)
        _set_client(client, resolved)
        return True
    except Exception:
        return False


def _run(action: Callable[[], T]) -> dict[str, Any]:
    last_exc: Exception | None = None
    attempts = max(1, STATE.retry_attempts)
    for _ in range(attempts):
        try:
            return _ok(action())
        except Exception as exc:  # pragma: no cover - runtime guard
            last_exc = exc
            if _is_transient_error(exc) and _reconnect_client():
                continue
            break
    return _error(last_exc or RuntimeError("Unknown xdbg MCP failure"))


def _require_client() -> X64DbgClient:
    client = STATE.client
    if client is None and _reconnect_client():
        client = STATE.client

    if client is None:
        raise RuntimeError("Not connected to x64dbg. Use start_session or connect_session first.")

    if not _is_client_alive(client):
        if _reconnect_client():
            client = STATE.client
    if client is None or not _is_client_alive(client):
        _clear_client()
        raise RuntimeError("Debugger session is stale/unreachable. Use connect_session/start_session.")
    return client


def _pe_bitness(exe_path: str) -> int:
    with open(exe_path, "rb") as handle:
        if handle.read(2) != b"MZ":
            raise ValueError(f"Not a PE file: {exe_path}")
        handle.seek(0x3C)
        pe_offset = struct.unpack("<I", handle.read(4))[0]
        handle.seek(pe_offset)
        if handle.read(4) != b"PE\x00\x00":
            raise ValueError(f"Invalid PE signature: {exe_path}")
        machine = struct.unpack("<H", handle.read(2))[0]
    if machine == 0x8664:
        return 64
    if machine == 0x14C:
        return 32
    raise ValueError(f"Unsupported PE machine: 0x{machine:X}")


def _coerce_xdbg_path(path_hint: str) -> str:
    path = Path(path_hint)
    if not path.is_dir():
        return path_hint
    candidates = [
        path / "x96dbg.exe",
        path / "x64dbg.exe",
        path / "x32dbg.exe",
        path / "release" / "x96dbg.exe",
        path / "release" / "x64dbg.exe",
        path / "release" / "x32dbg.exe",
        path / "release" / "x64" / "x64dbg.exe",
        path / "release" / "x32" / "x32dbg.exe",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return path_hint


def _debugger_bitness_from_name(executable_name: str) -> int | None:
    lower = executable_name.lower()
    if lower in ("x64dbg", "x64dbg.exe"):
        return 64
    if lower in ("x32dbg", "x32dbg.exe"):
        return 32
    return None


def _neighbor_debugger_candidates(candidate: Path, desired_bitness: int) -> list[Path]:
    desired_name = "x64dbg.exe" if desired_bitness == 64 else "x32dbg.exe"
    desired_folder = "x64" if desired_bitness == 64 else "x32"
    return [
        candidate.with_name(desired_name),
        candidate.parent / desired_name,
        candidate.parent / desired_folder / desired_name,
        candidate.parent / "release" / desired_name,
        candidate.parent / "release" / desired_folder / desired_name,
    ]


def _resolve_debugger_path(path_hint: str, target_exe: str = "") -> str:
    path_hint = _coerce_xdbg_path(path_hint)
    candidate = Path(path_hint)
    lower_name = candidate.name.lower()
    target_bitness: int | None = None
    if target_exe.strip():
        target_bitness = _pe_bitness(target_exe.strip())

    if lower_name in ("x96dbg", "x96dbg.exe"):
        desired = target_bitness or 64
        for neighbor in _neighbor_debugger_candidates(candidate, desired):
            if neighbor.is_file():
                return str(neighbor)
        dbg_name = "x64dbg.exe" if desired == 64 else "x32dbg.exe"
        raise FileNotFoundError(
            f"Cannot find {dbg_name} near {path_hint}. Pass x64dbg.exe/x32dbg.exe directly."
        )

    current_bitness = _debugger_bitness_from_name(lower_name)
    if target_bitness is not None and current_bitness is not None and target_bitness != current_bitness:
        for neighbor in _neighbor_debugger_candidates(candidate, target_bitness):
            if neighbor.is_file():
                return str(neighbor)

    return path_hint


def _validate_plugin_dependencies(resolved_xdbg_path: str) -> str:
    if STATE.skip_plugin_check:
        return ""

    dbg_path = Path(resolved_xdbg_path)
    bitness = _debugger_bitness_from_name(dbg_path.name)
    if bitness is None:
        return ""
    plugin_ext = ".dp64" if bitness == 64 else ".dp32"
    bitness_dir = "x64" if bitness == 64 else "x32"
    candidates = [
        dbg_path.parent / "plugins",
        dbg_path.parent / bitness_dir / "plugins",
        dbg_path.parent.parent / "plugins",
        dbg_path.parent.parent / bitness_dir / "plugins",
    ]
    deduped_candidates: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        normalized = str(candidate).lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        deduped_candidates.append(candidate)

    required_names = [
        f"x64dbg-automate{plugin_ext}",
        "libzmq-mt-4_3_5.dll",
    ]
    for plugin_dir in deduped_candidates:
        if all((plugin_dir / file_name).is_file() for file_name in required_names):
            return str(plugin_dir)

    checked_dirs = "\n".join(f"- {path}" for path in deduped_candidates)
    required_text = "\n".join(f"- {file_name}" for file_name in required_names)
    raise FileNotFoundError(
        "Missing x64dbg automate plugin dependencies.\n"
        f"Required files:\n{required_text}\n"
        f"Checked directories:\n{checked_dirs}"
    )


def _read_first_register(client: X64DbgClient, names: tuple[str, ...]) -> int:
    for name in names:
        try:
            value = client.get_reg(name)
            if isinstance(value, int):
                return value
        except Exception:
            continue
    raise RuntimeError(f"Cannot read any register from {', '.join(names)}")


def _is_ascii_path(path: str) -> bool:
    try:
        path.encode("ascii")
        return True
    except UnicodeEncodeError:
        return False


def _prepare_target_executable(target_exe: str) -> tuple[str, str]:
    target = target_exe.strip()
    if not target:
        return "", ""
    source = Path(target)
    if not source.is_file():
        raise FileNotFoundError(f"Target executable not found: {target}")
    if _is_ascii_path(target):
        return target, ""

    safe_dir = Path(tempfile.gettempdir()) / "xdbg-mcp-targets"
    safe_dir.mkdir(parents=True, exist_ok=True)
    safe_name = f"{source.stem}_{int(time.time() * 1000)}{source.suffix or '.exe'}"
    safe_copy = safe_dir / safe_name
    shutil.copy2(source, safe_copy)
    return str(safe_copy), str(safe_copy)


def _parse_int(value: int | str, *, allow_expression: bool) -> int:
    if isinstance(value, int):
        return value
    text = value.strip()
    if not text:
        raise ValueError("Empty numeric value")

    for base in (0, 16):
        try:
            return int(text, base)
        except ValueError:
            pass

    if allow_expression:
        client = _require_client()
        parsed, ok = client.eval_sync(text)
        if ok:
            return parsed
    raise ValueError(f"Cannot parse numeric value: {value}")


def _parse_address_or_symbol(value: int | str | None) -> int | str | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = value.strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        try:
            return int(text, 16)
        except ValueError:
            return text


def _parse_standard_bp_kind(kind: str) -> StandardBreakpointType:
    lut = {
        "short": StandardBreakpointType.Short,
        "long": StandardBreakpointType.Long,
        "ud2": StandardBreakpointType.Ud2,
        "ss": StandardBreakpointType.SingleShotInt3,
        "single": StandardBreakpointType.SingleShotInt3,
        "singleshotint3": StandardBreakpointType.SingleShotInt3,
    }
    key = kind.strip().lower()
    if key not in lut:
        raise ValueError("kind must be one of: short, long, ud2, ss")
    return lut[key]


def _parse_hw_kind(kind: str) -> HardwareBreakpointType:
    key = kind.strip().lower()
    if key not in ("r", "w", "x"):
        raise ValueError("kind must be one of: r, w, x")
    return HardwareBreakpointType(key)


def _parse_mem_kind(kind: str) -> MemoryBreakpointType:
    key = kind.strip().lower()
    if key not in ("r", "w", "x", "a"):
        raise ValueError("kind must be one of: r, w, x, a")
    return MemoryBreakpointType(key)


def _parse_bp_list_kind(kind: str) -> BreakpointType:
    lut = {
        "none": BreakpointType.BpNone,
        "normal": BreakpointType.BpNormal,
        "software": BreakpointType.BpNormal,
        "hardware": BreakpointType.BpHardware,
        "memory": BreakpointType.BpMemory,
        "dll": BreakpointType.BpDll,
        "exception": BreakpointType.BpException,
    }
    key = kind.strip().lower()
    if key not in lut:
        raise ValueError("kind must be one of: none, normal, hardware, memory, dll, exception")
    return lut[key]


def _hexdump(data: bytes, base_address: int) -> str:
    lines: list[str] = []
    for offset in range(0, len(data), 16):
        chunk = data[offset : offset + 16]
        hex_part = " ".join(f"{byte:02X}" for byte in chunk)
        ascii_part = "".join(chr(byte) if 0x20 <= byte < 0x7F else "." for byte in chunk)
        lines.append(f"0x{base_address + offset:016X}  {hex_part:<47}  {ascii_part}")
    return "\n".join(lines)


def _normalize_hex_blob(blob: str) -> bytes:
    normalized = blob.strip().replace("\\x", "").replace("0x", "").replace("0X", "")
    normalized = "".join(normalized.split())
    if not normalized:
        raise ValueError("hex_data is empty")
    if len(normalized) % 2 != 0:
        raise ValueError("hex_data must contain an even number of hex digits")
    return bytes.fromhex(normalized)


def _validate_rw_size(size: int) -> int:
    if size <= 0:
        raise ValueError("size must be > 0")
    if size > MAX_MEMORY_RW:
        raise ValueError(f"size exceeds limit: {MAX_MEMORY_RW} bytes")
    return size


@mcp.tool()
def health() -> dict[str, Any]:
    """Return server health and connection state."""
    client = STATE.client
    if client is not None and not _is_client_alive(client):
        if not _reconnect_client():
            _clear_client()
    live_client = STATE.client
    return _ok(
        {
            "connected": live_client is not None,
            "default_xdbg_path": STATE.xdbg_path,
            "resolved_xdbg_path": STATE.resolved_xdbg_path,
            "resolved_plugin_dir": STATE.resolved_plugin_dir,
            "session_pid": _session_pid_of(live_client),
            "last_session_pid": STATE.last_session_pid,
            "auto_reconnect": STATE.auto_reconnect,
        }
    )


@mcp.tool()
def configure_default_xdbg_path(xdbg_path: str) -> dict[str, Any]:
    """Set the default debugger path used by start/connect commands."""
    STATE.xdbg_path = xdbg_path.strip()
    STATE.resolved_xdbg_path = ""
    STATE.resolved_plugin_dir = ""
    return _ok({"default_xdbg_path": STATE.xdbg_path})


@mcp.tool()
def list_sessions() -> dict[str, Any]:
    """List active local x64dbg sessions."""
    return _run(lambda: X64DbgClient.list_sessions())


@mcp.tool()
def start_session(
    target_exe: str = "",
    cmdline: str = "",
    current_dir: str = "",
    xdbg_path: str = "",
) -> dict[str, Any]:
    """Launch x64dbg and optionally load an executable."""
    path_hint = (xdbg_path or STATE.xdbg_path).strip()
    try:
        prepared_target, copied_path = _prepare_target_executable(target_exe)
        resolved = _resolve_debugger_path(path_hint, prepared_target)
        plugin_dir = _validate_plugin_dependencies(resolved)
        client = X64DbgClient(resolved)
        debugger_pid = client.start_session(prepared_target, cmdline, current_dir)
        _set_client(client, resolved)
        STATE.xdbg_path = path_hint
        STATE.resolved_plugin_dir = plugin_dir
        return _ok(
            {
                "debugger_pid": debugger_pid,
                "resolved_xdbg_path": resolved,
                "resolved_plugin_dir": plugin_dir or None,
                "prepared_target_exe": prepared_target or None,
                "copied_target_exe": copied_path or None,
            }
        )
    except Exception as exc:
        _clear_client()
        STATE.resolved_plugin_dir = ""
        return _error(exc)


@mcp.tool()
def connect_session(session_pid: int | None = None, xdbg_path: str = "") -> dict[str, Any]:
    """Attach to an existing local x64dbg process by PID."""
    path_hint = (xdbg_path or STATE.xdbg_path).strip()
    try:
        pid = session_pid
        if pid is None:
            sessions = X64DbgClient.list_sessions()
            if STATE.last_session_pid is not None:
                for session in sessions:
                    if session.pid == STATE.last_session_pid:
                        pid = session.pid
                        break
            if pid is None:
                if len(sessions) != 1:
                    session_ids = [session.pid for session in sessions]
                    raise RuntimeError(
                        f"session_pid is required when active session count is not 1 (active={session_ids})"
                    )
                pid = sessions[0].pid

        resolved = _resolve_debugger_path(path_hint)
        plugin_dir = _validate_plugin_dependencies(resolved)
        client = X64DbgClient(resolved)
        client.attach_session(pid)
        _set_client(client, resolved)
        STATE.xdbg_path = path_hint
        STATE.resolved_plugin_dir = plugin_dir
        return _ok({"session_pid": pid, "resolved_xdbg_path": resolved, "resolved_plugin_dir": plugin_dir or None})
    except Exception as exc:
        _clear_client()
        STATE.resolved_plugin_dir = ""
        return _error(exc)


@mcp.tool()
def connect_remote(host: str, req_rep_port: int, pub_sub_port: int) -> dict[str, Any]:
    """Connect to a remote x64dbg automation endpoint."""
    try:
        remote_client = X64DbgClient.connect_remote(host, req_rep_port, pub_sub_port)
        _set_client(remote_client, "")
        STATE.resolved_plugin_dir = ""
        return _ok({"host": host, "req_rep_port": req_rep_port, "pub_sub_port": pub_sub_port})
    except Exception as exc:
        _clear_client()
        return _error(exc)


@mcp.tool()
def disconnect() -> dict[str, Any]:
    """Detach from current x64dbg session without killing the debugger."""
    if STATE.client is None:
        return _ok("already_disconnected")
    try:
        STATE.client.detach_session()
    finally:
        _clear_client()
    return _ok("disconnected")


@mcp.tool()
def terminate_session() -> dict[str, Any]:
    """Terminate current x64dbg debugger process and disconnect."""
    return _run(lambda: _terminate_session_impl())


def _terminate_session_impl() -> str:
    client = _require_client()
    client.terminate_session()
    _clear_client()
    return "terminated"


@mcp.tool()
def debugger_status() -> dict[str, Any]:
    """Get consolidated debugger status for the current session."""
    def action() -> dict[str, Any]:
        client = _require_client()
        return {
            "is_debugging": client.is_debugging(),
            "is_running": client.is_running(),
            "debugger_pid": client.get_debugger_pid(),
            "debugee_pid": client.debugee_pid(),
            "debugee_bitness": client.debugee_bitness(),
            "debugger_is_elevated": client.debugger_is_elevated(),
        }

    return _run(action)


@mcp.tool()
def command(cmd: str) -> dict[str, Any]:
    """Run a raw x64dbg command (equivalent to command bar input)."""
    def action() -> dict[str, Any]:
        client = _require_client()
        raw = cmd.strip()
        if not raw:
            raise ValueError("cmd is empty")

        executed = client.cmd_sync(raw)
        fallback_used = False
        if not executed:
            fallback_used = _try_command_fallback(client, raw)
            executed = fallback_used or client.cmd_sync(raw)
        return {"executed": executed, "command": raw, "fallback_used": fallback_used}

    return _run(action)


def _try_command_fallback(client: X64DbgClient, cmd: str) -> bool:
    lower = cmd.lower()
    for prefix in ("init ", "open ", "load "):
        if not lower.startswith(prefix):
            continue
        argument = cmd[len(prefix) :].strip().strip('"').strip("'")
        if not argument:
            return False
        return client.load_executable(argument)
    return False


@mcp.tool()
def evaluate(expression: str) -> dict[str, Any]:
    """Evaluate an x64dbg expression and return value + success flag."""
    def action() -> dict[str, Any]:
        value, success = _require_client().eval_sync(expression)
        return {"expression": expression, "value": value, "success": success}

    return _run(action)


@mcp.tool()
def go(pass_exceptions: bool = False, swallow_exceptions: bool = False) -> dict[str, Any]:
    """Resume execution."""
    if pass_exceptions and swallow_exceptions:
        return _error(ValueError("Cannot pass and swallow exceptions at the same time"))
    return _run(
        lambda: _require_client().go(
            pass_exceptions=pass_exceptions,
            swallow_exceptions=swallow_exceptions,
        )
    )


@mcp.tool()
def pause() -> dict[str, Any]:
    """Pause execution."""
    return _run(lambda: _require_client().pause())


@mcp.tool()
def step_into(step_count: int = 1) -> dict[str, Any]:
    """Single-step into."""
    return _run(lambda: _require_client().stepi(step_count=step_count))


@mcp.tool()
def step_over(step_count: int = 1) -> dict[str, Any]:
    """Single-step over."""
    return _run(lambda: _require_client().stepo(step_count=step_count))


@mcp.tool()
def run_to(address_or_symbol: int | str, timeout: int = 10, clear_on_timeout: bool = True) -> dict[str, Any]:
    """Run until address/symbol is reached via a temporary software breakpoint."""
    parsed = _parse_address_or_symbol(address_or_symbol)
    if parsed is None:
        return _error(ValueError("address_or_symbol is required"))

    def action() -> dict[str, Any]:
        client = _require_client()
        client.set_breakpoint(
            parsed,
            bp_type=StandardBreakpointType.SingleShotInt3,
            singleshoot=True,
        )
        client.go()
        reached = _wait_for_running_state(expect_running=False, timeout=timeout)
        if not reached and clear_on_timeout:
            try:
                client.clear_breakpoint(parsed)
            except Exception:
                pass

        payload: dict[str, Any] = {
            "target": parsed,
            "reached": reached,
        }
        if reached:
            ip = _read_first_register(client, ("cip", "rip", "eip"))
            payload["instruction_pointer"] = f"0x{ip:X}"
            try:
                payload["instruction"] = client.disassemble_at(ip)
            except Exception:
                payload["instruction"] = None
        return payload

    return _run(action)


@mcp.tool()
def wait_until_stopped(timeout: int = 10) -> dict[str, Any]:
    """Wait until target stops (breakpoint, pause, exception, etc.)."""
    return _run(lambda: _wait_for_running_state(expect_running=False, timeout=timeout))


@mcp.tool()
def wait_until_running(timeout: int = 10) -> dict[str, Any]:
    """Wait until target enters running state."""
    return _run(lambda: _wait_for_running_state(expect_running=True, timeout=timeout))


def _wait_for_running_state(expect_running: bool, timeout: int) -> bool:
    deadline = time.monotonic() + max(0.1, float(timeout))
    sleep_interval = max(0.01, STATE.wait_poll_ms / 1000.0)
    while time.monotonic() < deadline:
        try:
            running = bool(_require_client().is_running())
        except Exception as exc:
            if _is_transient_error(exc) and _reconnect_client():
                time.sleep(sleep_interval)
                continue
            raise
        if running == expect_running:
            return True
        time.sleep(sleep_interval)
    return False


@mcp.tool()
def get_registers() -> dict[str, Any]:
    """Get register snapshot."""
    return _run(lambda: _require_client().get_regs())


@mcp.tool()
def snapshot_context(
    include_stack: bool = True,
    stack_size: int = 128,
    stack_mode: str = "hexdump",
) -> dict[str, Any]:
    """Read registers + current instruction + optional stack snapshot in one call."""
    safe_stack_size = _validate_rw_size(stack_size) if include_stack else 0
    selected_mode = stack_mode.strip().lower()
    if selected_mode not in ("hex", "utf8", "hexdump"):
        return _error(ValueError("stack_mode must be one of: hex, utf8, hexdump"))

    def action() -> dict[str, Any]:
        client = _require_client()
        ip = _read_first_register(client, ("cip", "rip", "eip"))
        sp = _read_first_register(client, ("csp", "rsp", "esp"))
        payload: dict[str, Any] = {
            "instruction_pointer": f"0x{ip:X}",
            "stack_pointer": f"0x{sp:X}",
            "registers": client.get_regs(),
        }
        try:
            payload["instruction"] = client.disassemble_at(ip)
        except Exception:
            payload["instruction"] = None

        if include_stack:
            stack_data = client.read_memory(sp, safe_stack_size)
            stack_payload: dict[str, Any] = {
                "address": f"0x{sp:X}",
                "size": len(stack_data),
                "mode": selected_mode,
            }
            if selected_mode == "hex":
                stack_payload["data"] = stack_data.hex()
            elif selected_mode == "utf8":
                stack_payload["data"] = stack_data.decode("utf-8", errors="replace")
            else:
                stack_payload["data"] = _hexdump(stack_data, sp)
            payload["stack"] = stack_payload

        return payload

    return _run(action)


@mcp.tool()
def get_register(name: str) -> dict[str, Any]:
    """Get one register value."""
    def action() -> dict[str, Any]:
        value = _require_client().get_reg(name)
        return {"register": name, "value": value, "hex": f"0x{value:X}"}

    return _run(action)


@mcp.tool()
def set_register(name: str, value: int | str) -> dict[str, Any]:
    """Set one register value."""
    parsed_value = _parse_int(value, allow_expression=False)
    return _run(lambda: {"register": name, "value": parsed_value, "updated": _require_client().set_reg(name, parsed_value)})


@mcp.tool()
def read_memory(address: int | str, size: int, mode: str = "hex") -> dict[str, Any]:
    """Read process memory. mode: hex | utf8 | hexdump."""
    parsed_address = _parse_int(address, allow_expression=True)
    safe_size = _validate_rw_size(size)

    def action() -> dict[str, Any]:
        data = _require_client().read_memory(parsed_address, safe_size)
        selected_mode = mode.strip().lower()
        payload: dict[str, Any] = {
            "address": f"0x{parsed_address:X}",
            "size": len(data),
        }
        if selected_mode == "hex":
            payload["data"] = data.hex()
        elif selected_mode == "utf8":
            payload["data"] = data.decode("utf-8", errors="replace")
        elif selected_mode == "hexdump":
            payload["data"] = _hexdump(data, parsed_address)
        else:
            raise ValueError("mode must be one of: hex, utf8, hexdump")
        return payload

    return _run(action)


@mcp.tool()
def write_memory_hex(address: int | str, hex_data: str) -> dict[str, Any]:
    """Write bytes to process memory using a hex string."""
    parsed_address = _parse_int(address, allow_expression=True)
    parsed_data = _normalize_hex_blob(hex_data)
    _validate_rw_size(len(parsed_data))
    return _run(
        lambda: {
            "address": f"0x{parsed_address:X}",
            "written_size": len(parsed_data),
            "updated": _require_client().write_memory(parsed_address, parsed_data),
        }
    )


@mcp.tool()
def disassemble(address: int | str) -> dict[str, Any]:
    """Disassemble instruction at an address."""
    parsed_address = _parse_int(address, allow_expression=True)
    return _run(lambda: _require_client().disassemble_at(parsed_address))


@mcp.tool()
def assemble(address: int | str, instruction: str) -> dict[str, Any]:
    """Assemble one instruction at an address. Returns encoded byte size."""
    parsed_address = _parse_int(address, allow_expression=True)
    return _run(
        lambda: {
            "address": f"0x{parsed_address:X}",
            "instruction": instruction,
            "encoded_size": _require_client().assemble_at(parsed_address, instruction),
        }
    )


@mcp.tool()
def memory_map(max_entries: int = 256) -> dict[str, Any]:
    """Get memory map pages (truncated if max_entries is exceeded)."""

    def action() -> dict[str, Any]:
        pages = _require_client().memmap()
        max_entries_safe = max(1, max_entries)
        return {
            "total": len(pages),
            "truncated": len(pages) > max_entries_safe,
            "pages": pages[:max_entries_safe],
        }

    return _run(action)


@mcp.tool()
def set_breakpoint(
    address_or_symbol: int | str,
    kind: str = "short",
    name: str = "",
    singleshot: bool = False,
) -> dict[str, Any]:
    """Set software breakpoint. kind: short | long | ud2 | ss."""
    parsed = _parse_address_or_symbol(address_or_symbol)
    if parsed is None:
        return _error(ValueError("address_or_symbol is required"))
    bp_kind = _parse_standard_bp_kind(kind)
    bp_name = name.strip() or None
    return _run(
        lambda: {
            "set": _require_client().set_breakpoint(
                parsed,
                name=bp_name,
                bp_type=bp_kind,
                singleshoot=singleshot,
            )
        }
    )


@mcp.tool()
def clear_breakpoint(address_or_symbol: int | str | None = None) -> dict[str, Any]:
    """Clear one software breakpoint, or all software breakpoints if empty."""
    parsed = _parse_address_or_symbol(address_or_symbol)
    return _run(lambda: {"cleared": _require_client().clear_breakpoint(parsed)})


@mcp.tool()
def set_hardware_breakpoint(address_or_symbol: int | str, kind: str = "x", size: int = 1) -> dict[str, Any]:
    """Set hardware breakpoint. kind: r | w | x."""
    parsed = _parse_address_or_symbol(address_or_symbol)
    if parsed is None:
        return _error(ValueError("address_or_symbol is required"))
    return _run(
        lambda: {
            "set": _require_client().set_hardware_breakpoint(
                parsed,
                bp_type=_parse_hw_kind(kind),
                size=size,
            )
        }
    )


@mcp.tool()
def clear_hardware_breakpoint(address_or_symbol: int | str | None = None) -> dict[str, Any]:
    """Clear one hardware breakpoint, or all hardware breakpoints if empty."""
    parsed = _parse_address_or_symbol(address_or_symbol)
    return _run(lambda: {"cleared": _require_client().clear_hardware_breakpoint(parsed)})


@mcp.tool()
def set_memory_breakpoint(
    address_or_symbol: int | str,
    kind: str = "a",
    singleshot: bool = False,
) -> dict[str, Any]:
    """Set memory breakpoint. kind: r | w | x | a."""
    parsed = _parse_address_or_symbol(address_or_symbol)
    if parsed is None:
        return _error(ValueError("address_or_symbol is required"))
    return _run(
        lambda: {
            "set": _require_client().set_memory_breakpoint(
                parsed,
                bp_type=_parse_mem_kind(kind),
                singleshoot=singleshot,
            )
        }
    )


@mcp.tool()
def clear_memory_breakpoint(address_or_symbol: int | str | None = None) -> dict[str, Any]:
    """Clear one memory breakpoint, or all memory breakpoints if empty."""
    parsed = _parse_address_or_symbol(address_or_symbol)
    return _run(lambda: {"cleared": _require_client().clear_memory_breakpoint(parsed)})


@mcp.tool()
def list_breakpoints(kind: str = "normal") -> dict[str, Any]:
    """List breakpoints by kind: none | normal | hardware | memory | dll | exception."""
    parsed_kind = _parse_bp_list_kind(kind)
    return _run(lambda: _require_client().get_breakpoints(parsed_kind))


def main() -> None:
    parser = argparse.ArgumentParser(description="xdbg MCP server")
    parser.add_argument(
        "--xdbg-path",
        default=os.environ.get("XDBG_PATH", ""),
        help="Default path to x64dbg/x32dbg/x96dbg executable or install folder.",
    )
    args = parser.parse_args()
    if args.xdbg_path:
        STATE.xdbg_path = args.xdbg_path
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
