from __future__ import annotations

import argparse
import dataclasses
import enum
import hashlib
import json
import math
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
from x64dbg_automate.events import DbgEvent, EventType
from x64dbg_automate.models import (
    BreakpointType,
    HardwareBreakpointType,
    MemoryBreakpointType,
    StandardBreakpointType,
)

try:
    import pefile
except Exception:  # pragma: no cover - optional dependency fallback
    pefile = None

MAX_MEMORY_RW = 0x10000
TRANSIENT_ERROR_MARKERS = (
    "timed out",
    "deadline has elapsed",
    "resource temporarily unavailable",
    "operation cannot be accomplished in current state",
    "not connected to x64dbg",
    "session did not appear in a reasonable amount of time",
)
CORE_REGISTER_ALIASES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("ip", ("cip", "rip", "eip")),
    ("sp", ("csp", "rsp", "esp")),
    ("ax", ("rax", "eax")),
    ("bx", ("rbx", "ebx")),
    ("cx", ("rcx", "ecx")),
    ("dx", ("rdx", "edx")),
    ("si", ("rsi", "esi")),
    ("di", ("rdi", "edi")),
    ("bp", ("rbp", "ebp")),
    ("r8", ("r8",)),
    ("r9", ("r9",)),
    ("r10", ("r10",)),
    ("r11", ("r11",)),
    ("r12", ("r12",)),
    ("r13", ("r13",)),
    ("r14", ("r14",)),
    ("r15", ("r15",)),
)
STOP_RELEVANT_EVENT_TYPES: tuple[EventType, ...] = (
    EventType.EVENT_BREAKPOINT,
    EventType.EVENT_SYSTEMBREAKPOINT,
    EventType.EVENT_EXCEPTION,
    EventType.EVENT_PAUSE_DEBUG,
    EventType.EVENT_STEPPED,
    EventType.EVENT_STOP_DEBUG,
    EventType.EVENT_EXIT_PROCESS,
)
BREAKPOINT_QUERY_ORDER: tuple[BreakpointType, ...] = (
    BreakpointType.BpNormal,
    BreakpointType.BpHardware,
    BreakpointType.BpMemory,
    BreakpointType.BpDll,
    BreakpointType.BpException,
)
PAGE_PROTECT_FLAGS: tuple[tuple[int, str], ...] = (
    (0x100, "GUARD"),
    (0x200, "NOCACHE"),
    (0x400, "WRITECOMBINE"),
)
PAGE_PROTECT_BASE_NAMES: dict[int, str] = {
    0x01: "NOACCESS",
    0x02: "R",
    0x04: "RW",
    0x08: "WC",
    0x10: "X",
    0x20: "XR",
    0x40: "XRW",
    0x80: "XWC",
}
MEM_STATE_NAMES: dict[int, str] = {
    0x1000: "COMMIT",
    0x2000: "RESERVE",
    0x10000: "FREE",
}
MEM_TYPE_NAMES: dict[int, str] = {
    0x20000: "PRIVATE",
    0x40000: "MAPPED",
    0x1000000: "IMAGE",
}
PACKER_SECTION_HINTS: tuple[str, ...] = (
    ".vmp",
    "vmp",
    ".upx",
    "upx",
    ".themida",
    "themida",
    ".enigma",
    "enigma",
    ".mpress",
    "mpress",
    ".aspack",
    "aspack",
    ".petite",
    "petite",
    ".packed",
    "packed",
    ".stub",
)
PACKER_API_HINTS: tuple[str, ...] = (
    "VirtualAlloc",
    "VirtualProtect",
    "VirtualQuery",
    "WriteProcessMemory",
    "MapViewOfFile",
    "CreateFileMapping",
    "LoadLibraryA",
    "LoadLibraryW",
    "GetProcAddress",
    "SetUnhandledExceptionFilter",
    "AddVectoredExceptionHandler",
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "NtQueryInformationProcess",
    "LdrLoadDll",
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


@dataclass(frozen=True)
class SoftwareBreakpointSpec:
    target: int | str
    kind: StandardBreakpointType
    name: str | None
    singleshot: bool


@dataclass(frozen=True)
class HardwareBreakpointSpec:
    target: int | str
    kind: HardwareBreakpointType
    size: int


@dataclass(frozen=True)
class MemoryBreakpointSpec:
    target: int | str
    kind: MemoryBreakpointType
    singleshot: bool


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
    event_drain_limit: int = _env_int("XDBG_MCP_EVENT_DRAIN_LIMIT", 64)
    software_breakpoints: list[SoftwareBreakpointSpec] = dataclasses.field(default_factory=list)
    hardware_breakpoints: list[HardwareBreakpointSpec] = dataclasses.field(default_factory=list)
    memory_breakpoints: list[MemoryBreakpointSpec] = dataclasses.field(default_factory=list)
    reconnect_count: int = 0
    last_reconnect_time: float | None = None


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


def _target_key(value: int | str) -> str:
    if isinstance(value, int):
        return f"int:{value}"
    return f"str:{value.strip().lower()}"


def _remember_software_breakpoint(spec: SoftwareBreakpointSpec) -> None:
    key = _target_key(spec.target)
    for index, existing in enumerate(STATE.software_breakpoints):
        if _target_key(existing.target) == key and existing.kind == spec.kind:
            STATE.software_breakpoints[index] = spec
            return
    STATE.software_breakpoints.append(spec)


def _remember_hardware_breakpoint(spec: HardwareBreakpointSpec) -> None:
    key = _target_key(spec.target)
    for index, existing in enumerate(STATE.hardware_breakpoints):
        if (
            _target_key(existing.target) == key
            and existing.kind == spec.kind
            and existing.size == spec.size
        ):
            STATE.hardware_breakpoints[index] = spec
            return
    STATE.hardware_breakpoints.append(spec)


def _remember_memory_breakpoint(spec: MemoryBreakpointSpec) -> None:
    key = _target_key(spec.target)
    for index, existing in enumerate(STATE.memory_breakpoints):
        if _target_key(existing.target) == key and existing.kind == spec.kind:
            STATE.memory_breakpoints[index] = spec
            return
    STATE.memory_breakpoints.append(spec)


def _forget_software_breakpoint(target: int | str | None) -> None:
    if target is None:
        STATE.software_breakpoints.clear()
        return
    key = _target_key(target)
    STATE.software_breakpoints = [
        spec for spec in STATE.software_breakpoints if _target_key(spec.target) != key
    ]


def _forget_hardware_breakpoint(target: int | str | None) -> None:
    if target is None:
        STATE.hardware_breakpoints.clear()
        return
    key = _target_key(target)
    STATE.hardware_breakpoints = [
        spec for spec in STATE.hardware_breakpoints if _target_key(spec.target) != key
    ]


def _forget_memory_breakpoint(target: int | str | None) -> None:
    if target is None:
        STATE.memory_breakpoints.clear()
        return
    key = _target_key(target)
    STATE.memory_breakpoints = [
        spec for spec in STATE.memory_breakpoints if _target_key(spec.target) != key
    ]


def _reapply_recorded_breakpoints(client: X64DbgClient) -> dict[str, Any]:
    restored = {"software": 0, "hardware": 0, "memory": 0, "errors": []}

    for spec in STATE.software_breakpoints:
        try:
            client.set_breakpoint(
                spec.target,
                name=spec.name,
                bp_type=spec.kind,
                singleshoot=spec.singleshot,
            )
            restored["software"] += 1
        except Exception as exc:
            restored["errors"].append(
                {
                    "type": "software",
                    "target": spec.target,
                    "error": str(exc),
                }
            )

    for spec in STATE.hardware_breakpoints:
        try:
            client.set_hardware_breakpoint(
                spec.target,
                bp_type=spec.kind,
                size=spec.size,
            )
            restored["hardware"] += 1
        except Exception as exc:
            restored["errors"].append(
                {
                    "type": "hardware",
                    "target": spec.target,
                    "error": str(exc),
                }
            )

    for spec in STATE.memory_breakpoints:
        try:
            client.set_memory_breakpoint(
                spec.target,
                bp_type=spec.kind,
                singleshoot=spec.singleshot,
            )
            restored["memory"] += 1
        except Exception as exc:
            restored["errors"].append(
                {
                    "type": "memory",
                    "target": spec.target,
                    "error": str(exc),
                }
            )

    return restored


def _event_to_payload(event: DbgEvent) -> dict[str, Any]:
    payload: dict[str, Any] = {"event_type": str(event.event_type)}
    event_data = getattr(event, "event_data", None)
    if event_data is not None and hasattr(event_data, "model_dump"):
        payload["event_data"] = _to_jsonable(event_data.model_dump())
    else:
        payload["event_data"] = None
    return payload


def _drain_debug_events(client: X64DbgClient, max_events: int | None = None) -> list[DbgEvent]:
    limit = max_events or STATE.event_drain_limit
    safe_limit = max(1, int(limit))
    drained: list[DbgEvent] = []
    for _ in range(safe_limit):
        event = client.get_latest_debug_event()
        if event is None:
            break
        drained.append(event)
    drained.reverse()
    return drained


def _derive_stop_reason(events: list[DbgEvent]) -> tuple[str, dict[str, Any] | None]:
    priority_groups: tuple[tuple[EventType, ...], ...] = (
        (EventType.EVENT_EXCEPTION,),
        (EventType.EVENT_BREAKPOINT, EventType.EVENT_SYSTEMBREAKPOINT),
        (EventType.EVENT_STEPPED,),
        (EventType.EVENT_EXIT_PROCESS,),
        (EventType.EVENT_STOP_DEBUG,),
        (EventType.EVENT_PAUSE_DEBUG,),
    )
    for group in priority_groups:
        for event in reversed(events):
            if event.event_type not in group:
                continue
            payload = _event_to_payload(event)
            if event.event_type in (EventType.EVENT_BREAKPOINT, EventType.EVENT_SYSTEMBREAKPOINT):
                return "breakpoint", payload
            if event.event_type == EventType.EVENT_EXCEPTION:
                return "exception", payload
            if event.event_type == EventType.EVENT_PAUSE_DEBUG:
                return "paused", payload
            if event.event_type == EventType.EVENT_STEPPED:
                return "stepped", payload
            if event.event_type == EventType.EVENT_EXIT_PROCESS:
                return "process_exit", payload
            if event.event_type == EventType.EVENT_STOP_DEBUG:
                return "debug_stopped", payload
            return str(event.event_type).lower(), payload
    return "unknown", None


def _breakpoint_detail_label(bp_type: BreakpointType | int | None) -> str:
    mapping = {
        BreakpointType.BpNormal: "software",
        BreakpointType.BpHardware: "hardware",
        BreakpointType.BpMemory: "memory",
        BreakpointType.BpDll: "dll",
        BreakpointType.BpException: "exception_breakpoint",
    }
    try:
        normalized = bp_type if isinstance(bp_type, BreakpointType) else BreakpointType(bp_type or 0)
    except Exception:
        return "unknown"
    return mapping.get(normalized, str(normalized).lower())


def _snapshot_breakpoints(client: X64DbgClient) -> dict[int, list[dict[str, Any]]]:
    snapshot: dict[int, list[dict[str, Any]]] = {}
    seen: set[tuple[int, int, str, str]] = set()
    for kind in BREAKPOINT_QUERY_ORDER:
        try:
            items = client.get_breakpoints(kind)
        except Exception:
            continue
        for bp in items:
            payload = _to_jsonable(bp)
            if not isinstance(payload, dict):
                continue
            addr = int(payload.get("addr", -1))
            if addr < 0:
                continue
            key = (
                addr,
                int(payload.get("type", 0)),
                str(payload.get("mod", "")),
                str(payload.get("name", "")),
            )
            if key in seen:
                continue
            seen.add(key)
            payload["detail"] = _breakpoint_detail_label(getattr(bp, "type", None))
            snapshot.setdefault(addr, []).append(payload)
    return snapshot


def _find_breakpoints_at_address(client: X64DbgClient, address: int) -> list[dict[str, Any]]:
    snapshot = _snapshot_breakpoints(client)
    matches = snapshot.get(address, [])
    return matches


def _find_memory_page_for_address(client: X64DbgClient, address: int) -> dict[str, Any] | None:
    try:
        pages = client.memmap()
    except Exception:
        return None
    for page in pages:
        base_address = int(getattr(page, "base_address", 0))
        region_size = int(getattr(page, "region_size", 0))
        if base_address <= address < (base_address + max(0, region_size)):
            payload = _to_jsonable(page)
            if isinstance(payload, dict):
                payload["offset"] = address - base_address
                return payload
            return None
    return None


def _infer_stop_details(client: X64DbgClient, instruction_pointer_value: int | None) -> dict[str, Any]:
    if not isinstance(instruction_pointer_value, int):
        return {}
    payload: dict[str, Any] = {}
    matched_breakpoints = _find_breakpoints_at_address(client, instruction_pointer_value)
    if matched_breakpoints:
        payload["matched_breakpoints"] = matched_breakpoints
        primary = matched_breakpoints[0]
        payload["inferred_stop_reason"] = "breakpoint"
        payload["inferred_stop_reason_detail"] = primary.get("detail", "unknown")
        payload["inferred_stop_event"] = {
            "event_type": "INFERRED_BREAKPOINT",
            "event_data": primary,
        }
    instruction_page = _find_memory_page_for_address(client, instruction_pointer_value)
    if instruction_page is not None:
        payload["instruction_page"] = instruction_page
    return payload


def _events_since_last_resume(events: list[DbgEvent]) -> list[DbgEvent]:
    for index in range(len(events) - 1, -1, -1):
        if events[index].event_type == EventType.EVENT_RESUME_DEBUG:
            return events[index:]
    return events


def _build_stop_details_from_events(
    client: X64DbgClient,
    events: list[DbgEvent],
    *,
    include_events: bool,
    instruction_pointer_value: int | None = None,
) -> dict[str, Any]:
    stop_reason, stop_event = _derive_stop_reason(events)
    inferred = _infer_stop_details(client, instruction_pointer_value)
    if stop_reason in ("unknown", "paused") and inferred.get("inferred_stop_reason"):
        stop_reason = str(inferred["inferred_stop_reason"])
        stop_event = inferred.get("inferred_stop_event")
    payload: dict[str, Any] = {
        "stop_reason": stop_reason,
        "stop_event": stop_event,
    }
    if stop_event is not None:
        payload["stop_reason_source"] = "events"
    if "inferred_stop_reason" in inferred:
        payload["inferred_stop_reason"] = inferred["inferred_stop_reason"]
        payload["inferred_stop_reason_detail"] = inferred.get("inferred_stop_reason_detail")
        if payload.get("stop_reason_source") is None:
            payload["stop_reason_source"] = "inferred"
    if "matched_breakpoints" in inferred:
        payload["matched_breakpoints"] = inferred["matched_breakpoints"]
    if "instruction_page" in inferred:
        payload["instruction_page"] = inferred["instruction_page"]
    if include_events:
        payload["events"] = [_event_to_payload(item) for item in events]
    return payload


def _apply_breakpoint_inference(
    wait_result: dict[str, Any],
    matched_breakpoints: list[dict[str, Any]],
    *,
    source: str,
) -> dict[str, Any]:
    if not matched_breakpoints:
        return wait_result
    payload = dict(wait_result)
    payload["matched_breakpoints"] = matched_breakpoints
    payload["inferred_stop_reason"] = "breakpoint"
    payload["inferred_stop_reason_detail"] = matched_breakpoints[0].get("detail", "unknown")
    if payload.get("stop_reason") in ("unknown", "paused", None):
        payload["stop_reason"] = "breakpoint"
        payload["stop_event"] = {
            "event_type": "INFERRED_BREAKPOINT",
            "event_data": matched_breakpoints[0],
        }
        payload["stop_reason_source"] = source
    return payload


def _collect_stop_details(
    client: X64DbgClient,
    *,
    include_events: bool,
    max_events: int | None = None,
    instruction_pointer_value: int | None = None,
) -> dict[str, Any]:
    events = _drain_debug_events(client, max_events=max_events)
    return _build_stop_details_from_events(
        client,
        events,
        include_events=include_events,
        instruction_pointer_value=instruction_pointer_value,
    )


def _did_hit_target(wait_result: dict[str, Any], target_address: int | None) -> bool:
    if target_address is None or not bool(wait_result.get("matched")):
        return False
    ip_value = wait_result.get("instruction_pointer_value")
    if isinstance(ip_value, int) and ip_value == target_address:
        return True

    stop_event = wait_result.get("stop_event")
    if isinstance(stop_event, dict):
        event_data = stop_event.get("event_data")
        if isinstance(event_data, dict):
            stop_addr = event_data.get("addr")
            if isinstance(stop_addr, int):
                return stop_addr == target_address
    return False


def _compact_stop_summary(wait_result: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "stop_reason": wait_result.get("stop_reason"),
        "stop_reason_source": wait_result.get("stop_reason_source"),
        "instruction_pointer": wait_result.get("instruction_pointer"),
        "instruction_pointer_value": wait_result.get("instruction_pointer_value"),
        "instruction": wait_result.get("instruction"),
        "stop_event": wait_result.get("stop_event"),
    }
    if "matched_breakpoints" in wait_result:
        summary["matched_breakpoints"] = wait_result.get("matched_breakpoints")
    if "instruction_page" in wait_result:
        summary["instruction_page"] = wait_result.get("instruction_page")
    events = wait_result.get("events")
    if isinstance(events, list) and events:
        summary["events"] = events
    return summary


def _set_first_register(client: X64DbgClient, names: tuple[str, ...], value: int) -> str:
    last_error: Exception | None = None
    for name in names:
        try:
            if client.set_reg(name, value):
                return name
        except Exception as exc:
            last_error = exc
    if last_error is not None:
        raise RuntimeError(f"Cannot set register {names}: {last_error}")
    raise RuntimeError(f"Cannot set register {names}")


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
        _reapply_recorded_breakpoints(client)
        STATE.reconnect_count += 1
        STATE.last_reconnect_time = time.time()
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


def _capture_core_registers(client: X64DbgClient) -> dict[str, int]:
    snapshot: dict[str, int] = {}
    for logical_name, aliases in CORE_REGISTER_ALIASES:
        try:
            snapshot[logical_name] = _read_first_register(client, aliases)
        except Exception:
            continue
    return snapshot


def _diff_register_snapshots(before: dict[str, int], after: dict[str, int]) -> dict[str, Any]:
    changed: dict[str, Any] = {}
    for key in sorted(set(before) | set(after)):
        old_value = before.get(key)
        new_value = after.get(key)
        if old_value == new_value:
            continue
        changed[key] = {
            "before": old_value,
            "after": new_value,
            "before_hex": f"0x{old_value:X}" if isinstance(old_value, int) else None,
            "after_hex": f"0x{new_value:X}" if isinstance(new_value, int) else None,
        }
    return changed


def _parse_step_mode(mode: str) -> str:
    selected = mode.strip().lower()
    if selected not in ("into", "over"):
        raise ValueError("mode must be one of: into, over")
    return selected


def _parse_pattern_bytes(pattern: str, pattern_type: str) -> tuple[bytes, str]:
    text = pattern.strip()
    if not text:
        raise ValueError("pattern is empty")
    selected = pattern_type.strip().lower()
    if selected == "hex":
        return _normalize_hex_blob(text), selected
    if selected == "ascii":
        return text.encode("utf-8"), selected
    if selected == "utf16le":
        return text.encode("utf-16le"), selected
    raise ValueError("pattern_type must be one of: hex, ascii, utf16le")


def _encode_text_bytes(text: str, encoding: str, append_null: bool) -> tuple[bytes, str]:
    selected = encoding.strip().lower()
    if selected in ("utf8", "utf-8"):
        data = text.encode("utf-8")
        if append_null:
            data += b"\x00"
        return data, "utf-8"
    if selected in ("ascii",):
        data = text.encode("ascii")
        if append_null:
            data += b"\x00"
        return data, "ascii"
    if selected in ("utf16le", "utf-16le"):
        data = text.encode("utf-16le")
        if append_null:
            data += b"\x00\x00"
        return data, "utf-16le"
    raise ValueError("encoding must be one of: ascii, utf-8, utf-16le")


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


def _parse_event_type(name: str) -> EventType:
    normalized = name.strip().upper()
    try:
        return EventType(normalized)
    except Exception as exc:
        supported = ", ".join(item.value for item in EventType)
        raise ValueError(f"event_type must be one of: {supported}") from exc


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


def _protect_base(value: int) -> int:
    return int(value) & 0xFF


def _protect_to_text(value: int) -> str:
    base = _protect_base(value)
    parts = [PAGE_PROTECT_BASE_NAMES.get(base, f"0x{base:X}")]
    for flag, name in PAGE_PROTECT_FLAGS:
        if int(value) & flag:
            parts.append(name)
    return "|".join(parts)


def _state_to_text(value: int) -> str:
    return MEM_STATE_NAMES.get(int(value), f"0x{int(value):X}")


def _type_to_text(value: int) -> str:
    return MEM_TYPE_NAMES.get(int(value), f"0x{int(value):X}")


def _is_executable_protect(value: int) -> bool:
    return _protect_base(value) in (0x10, 0x20, 0x40, 0x80)


def _is_writable_protect(value: int) -> bool:
    return _protect_base(value) in (0x04, 0x08, 0x40, 0x80)


def _decode_section_name(raw_name: bytes) -> str:
    return raw_name.rstrip(b"\x00").decode("ascii", errors="replace")


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = float(len(data))
    entropy = 0.0
    for count in counts:
        if count == 0:
            continue
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def _read_file_chunks(path: Path, chunk_size: int = 0x10000) -> bytes:
    with path.open("rb") as fh:
        return fh.read()


def _pe_directory_size(pe: Any, name: str) -> int:
    directory_indices = {
        "IMAGE_DIRECTORY_ENTRY_IMPORT": 1,
        "IMAGE_DIRECTORY_ENTRY_BASERELOC": 5,
        "IMAGE_DIRECTORY_ENTRY_TLS": 9,
    }
    try:
        index = directory_indices[name]
        directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[index]
    except Exception:
        return 0
    size = int(getattr(directory, "Size", 0) or 0)
    return size


def _pe_has_tls_callbacks(pe: Any) -> bool:
    try:
        directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[9]
        return bool(int(getattr(directory, "VirtualAddress", 0) or 0))
    except Exception:
        return False


def _section_characteristics_summary(section: Any) -> dict[str, bool]:
    chars = int(getattr(section, "Characteristics", 0))
    return {
        "executable": bool(chars & 0x20000000),
        "readable": bool(chars & 0x40000000),
        "writable": bool(chars & 0x80000000),
    }


def _main_module_pages(client: X64DbgClient) -> list[Any]:
    pages = client.memmap()
    image_pages = [
        page
        for page in pages
        if int(getattr(page, "type", 0)) == 0x1000000 and str(getattr(page, "info", "")).strip()
    ]
    if not image_pages:
        return []
    counts: dict[int, int] = {}
    for page in image_pages:
        base = int(getattr(page, "allocation_base", 0))
        counts[base] = counts.get(base, 0) + 1
    best_base = max(counts, key=counts.get)
    return [page for page in image_pages if int(getattr(page, "allocation_base", 0)) == best_base]


def _page_payload(page: Any) -> dict[str, Any]:
    base_address = int(getattr(page, "base_address", 0))
    region_size = int(getattr(page, "region_size", 0))
    protect = int(getattr(page, "protect", 0))
    state = int(getattr(page, "state", 0))
    page_type = int(getattr(page, "type", 0))
    return {
        "base_address": f"0x{base_address:X}",
        "base_address_value": base_address,
        "allocation_base": f"0x{int(getattr(page, 'allocation_base', 0)):X}",
        "allocation_base_value": int(getattr(page, "allocation_base", 0)),
        "region_size": region_size,
        "protect": protect,
        "protect_text": _protect_to_text(protect),
        "state": state,
        "state_text": _state_to_text(state),
        "type": page_type,
        "type_text": _type_to_text(page_type),
        "info": str(getattr(page, "info", "")),
        "is_executable": _is_executable_protect(protect),
        "is_writable": _is_writable_protect(protect),
    }


def _chunked_read_process_memory(client: X64DbgClient, address: int, size: int) -> bytes:
    remaining = max(0, int(size))
    cursor = int(address)
    chunks: list[bytes] = []
    while remaining > 0:
        to_read = min(MAX_MEMORY_RW, remaining)
        chunk = client.read_memory(cursor, to_read)
        if not chunk:
            break
        chunks.append(chunk)
        read_size = len(chunk)
        cursor += read_size
        remaining -= read_size
        if read_size < to_read:
            break
    return b"".join(chunks)


def _score_page_suspicion(
    page_payload: dict[str, Any],
    *,
    current_ip: int | None,
) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    base_address = int(page_payload.get("base_address_value", 0))
    region_size = int(page_payload.get("region_size", 0))
    info_text = str(page_payload.get("info", "")).lower()
    if page_payload.get("is_executable") and page_payload.get("type_text") == "PRIVATE":
        score += 40
        reasons.append("private executable page")
    if page_payload.get("is_executable") and page_payload.get("is_writable"):
        score += 35
        reasons.append("writable executable page")
    if page_payload.get("type_text") == "PRIVATE" and "heap" not in info_text and region_size >= 0x1000:
        score += 10
        reasons.append("private committed region")
    if any(hint in info_text for hint in ("vmp", ".hello", ".themida", ".packed")):
        score += 15
        reasons.append("suspicious section/module label")
    if isinstance(current_ip, int) and base_address <= current_ip < (base_address + max(0, region_size)):
        score += 50
        reasons.append("current IP is inside this page")
    return score, reasons


def _require_pefile() -> Any:
    if pefile is None:
        raise RuntimeError("pefile is required for PE profiling. Install dependency: pefile")
    return pefile


def _profile_pe_file_impl(file_path: str) -> dict[str, Any]:
    pe_mod = _require_pefile()
    path = Path(file_path).expanduser()
    if not path.is_file():
        raise FileNotFoundError(f"PE file not found: {file_path}")
    raw = _read_file_chunks(path)
    pe = pe_mod.PE(str(path), fast_load=False)
    sha256 = hashlib.sha256(raw).hexdigest()

    section_payloads: list[dict[str, Any]] = []
    executable_high_entropy = 0
    suspicious_section_names: list[str] = []
    entry_section_name = ""
    entry_rva = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    try:
        entry_section = pe.get_section_by_rva(entry_rva)
    except Exception:
        entry_section = None
    if entry_section is not None:
        entry_section_name = _decode_section_name(entry_section.Name)

    for section in pe.sections:
        name = _decode_section_name(section.Name)
        data = section.get_data()
        entropy = _shannon_entropy(data)
        flags = _section_characteristics_summary(section)
        name_lower = name.lower()
        suspicious_name = any(hint in name_lower for hint in PACKER_SECTION_HINTS)
        if suspicious_name:
            suspicious_section_names.append(name)
        if flags["executable"] and entropy >= 7.2:
            executable_high_entropy += 1
        section_payloads.append(
            {
                "name": name,
                "virtual_address": f"0x{int(section.VirtualAddress):X}",
                "virtual_size": int(section.Misc_VirtualSize),
                "raw_size": int(section.SizeOfRawData),
                "entropy": round(entropy, 3),
                "executable": flags["executable"],
                "readable": flags["readable"],
                "writable": flags["writable"],
                "suspicious_name": suspicious_name,
            }
        )

    imports: list[dict[str, Any]] = []
    imported_names: list[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            functions: list[str] = []
            for imp in entry.imports:
                if imp.name:
                    decoded = imp.name.decode("ascii", errors="replace")
                    functions.append(decoded)
                    imported_names.append(decoded)
            imports.append(
                {
                    "dll": entry.dll.decode("ascii", errors="replace"),
                    "function_count": len(functions),
                    "functions_preview": functions[:16],
                }
            )

    import_hits = sorted({name for name in imported_names if name in PACKER_API_HINTS})
    indicator_items: list[dict[str, Any]] = []
    score = 0

    if any(name.lower() in (".vmp0", ".vmp1", ".vmp2") for name in suspicious_section_names):
        indicator_items.append({"weight": 8, "reason": "classic VMProtect section names present"})
        score += 8
    elif any("vmp" in name.lower() for name in suspicious_section_names):
        indicator_items.append({"weight": 6, "reason": "section names look VMProtect-like"})
        score += 6

    if executable_high_entropy:
        indicator_items.append(
            {
                "weight": 3,
                "reason": f"{executable_high_entropy} executable section(s) have high entropy",
            }
        )
        score += 3

    if entry_section_name and entry_section_name.lower() not in (".text", "text"):
        indicator_items.append(
            {
                "weight": 2,
                "reason": f"entry point is in non-standard section {entry_section_name}",
            }
        )
        score += 2

    if len(imported_names) <= 24 and len(import_hits) >= 3:
        indicator_items.append(
            {
                "weight": 4,
                "reason": "small import table dominated by loader/protection APIs",
            }
        )
        score += 4
    elif import_hits:
        indicator_items.append(
            {
                "weight": 1,
                "reason": f"packer-related imports present: {', '.join(import_hits[:6])}",
            }
        )
        score += 1

    if _pe_has_tls_callbacks(pe):
        indicator_items.append({"weight": 2, "reason": "TLS callbacks present"})
        score += 2

    if _pe_directory_size(pe, "IMAGE_DIRECTORY_ENTRY_BASERELOC") == 0 and executable_high_entropy:
        indicator_items.append({"weight": 1, "reason": "relocations stripped alongside packed-like sections"})
        score += 1

    label = "likely_unpacked"
    confidence = "low"
    if any(name.lower() in (".vmp0", ".vmp1", ".vmp2") for name in suspicious_section_names):
        label = "likely_vmp"
        confidence = "high"
    elif score >= 10:
        label = "vmp_like_or_custom_vm"
        confidence = "medium"
    elif score >= 6:
        label = "generic_packed"
        confidence = "medium"
    elif score >= 3:
        label = "possibly_protected"
        confidence = "low"

    return {
        "file_path": str(path),
        "sha256": sha256,
        "size": len(raw),
        "machine": hex(int(pe.FILE_HEADER.Machine)),
        "image_base": f"0x{int(pe.OPTIONAL_HEADER.ImageBase):X}",
        "entry_point": f"0x{int(pe.OPTIONAL_HEADER.ImageBase) + entry_rva:X}",
        "entry_section": entry_section_name or None,
        "section_count": len(section_payloads),
        "sections": section_payloads,
        "import_dll_count": len(imports),
        "import_function_count": len(imported_names),
        "imports_preview": imports[:12],
        "tls_callbacks_present": _pe_has_tls_callbacks(pe),
        "packer_api_hits": import_hits,
        "indicators": indicator_items,
        "classification": {
            "label": label,
            "confidence": confidence,
            "score": score,
            "heuristic": True,
        },
    }


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
            "reconnect_count": STATE.reconnect_count,
            "last_reconnect_time": STATE.last_reconnect_time,
            "tracked_breakpoints": {
                "software": len(STATE.software_breakpoints),
                "hardware": len(STATE.hardware_breakpoints),
                "memory": len(STATE.memory_breakpoints),
            },
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
        STATE.software_breakpoints.clear()
        STATE.hardware_breakpoints.clear()
        STATE.memory_breakpoints.clear()
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
        STATE.software_breakpoints.clear()
        STATE.hardware_breakpoints.clear()
        STATE.memory_breakpoints.clear()
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
        STATE.software_breakpoints.clear()
        STATE.hardware_breakpoints.clear()
        STATE.memory_breakpoints.clear()
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
    STATE.software_breakpoints.clear()
    STATE.hardware_breakpoints.clear()
    STATE.memory_breakpoints.clear()
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
def step_trace(step_count: int = 16, mode: str = "into", include_register_diff: bool = True) -> dict[str, Any]:
    """Trace N steps with instruction pointer/instruction and optional register diffs."""
    safe_steps = max(1, min(int(step_count), 4096))
    selected_mode = _parse_step_mode(mode)

    def action() -> dict[str, Any]:
        client = _require_client()
        trace: list[dict[str, Any]] = []
        previous_regs = _capture_core_registers(client) if include_register_diff else {}
        for index in range(safe_steps):
            if selected_mode == "into":
                stepped = client.stepi(step_count=1)
            else:
                stepped = client.stepo(step_count=1)

            ip = _read_first_register(client, ("cip", "rip", "eip"))
            step_payload: dict[str, Any] = {
                "index": index + 1,
                "stepped": bool(stepped),
                "instruction_pointer": f"0x{ip:X}",
            }
            try:
                step_payload["instruction"] = client.disassemble_at(ip)
            except Exception:
                step_payload["instruction"] = None

            if include_register_diff:
                current_regs = _capture_core_registers(client)
                step_payload["changed_registers"] = _diff_register_snapshots(previous_regs, current_regs)
                previous_regs = current_regs

            trace.append(step_payload)
            if not stepped:
                break

        return {
            "mode": selected_mode,
            "requested_steps": safe_steps,
            "actual_steps": len(trace),
            "trace": trace,
        }

    return _run(action)


@mcp.tool()
def run_until_expr(
    expression: str,
    timeout: int = 30,
    max_stops: int = 50,
    pass_exceptions: bool = False,
    swallow_exceptions: bool = False,
    pause_on_timeout: bool = True,
) -> dict[str, Any]:
    """Run until expression evaluates to non-zero, or timeout/stop limit is reached."""
    expr = expression.strip()
    if not expr:
        return _error(ValueError("expression is empty"))
    if pass_exceptions and swallow_exceptions:
        return _error(ValueError("Cannot pass and swallow exceptions at the same time"))
    safe_timeout = max(1, int(timeout))
    safe_max_stops = max(1, int(max_stops))

    def action() -> dict[str, Any]:
        client = _require_client()
        deadline = time.monotonic() + float(safe_timeout)
        stops = 0
        last_value = 0
        last_success = False
        reached = False

        while time.monotonic() < deadline:
            last_value, last_success = client.eval_sync(expr)
            if last_success and last_value != 0:
                reached = True
                break

            if stops >= safe_max_stops:
                break

            if not client.is_running():
                client.go(
                    pass_exceptions=pass_exceptions,
                    swallow_exceptions=swallow_exceptions,
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            wait_result = _wait_for_running_state(
                expect_running=False,
                timeout=max(1, int(remaining)),
                clear_stale_events=False,
                include_events=False,
            )
            if not bool(wait_result.get("matched")):
                if pause_on_timeout:
                    try:
                        client.pause()
                    except Exception:
                        pass
                break
            stops += 1

        payload: dict[str, Any] = {
            "expression": expr,
            "reached": reached,
            "stops": stops,
            "max_stops": safe_max_stops,
            "timeout": safe_timeout,
            "last_value": last_value,
            "last_success": last_success,
            "timed_out": (not reached) and (time.monotonic() >= deadline),
        }
        try:
            ip = _read_first_register(client, ("cip", "rip", "eip"))
            payload["instruction_pointer"] = f"0x{ip:X}"
            payload["instruction"] = client.disassemble_at(ip)
        except Exception:
            payload["instruction"] = None
        return payload

    return _run(action)


@mcp.tool()
def run_to(
    address_or_symbol: int | str,
    timeout: int = 10,
    clear_on_timeout: bool = True,
    continue_on_unrelated_stop: bool = True,
    max_unrelated_stops: int = 16,
    include_unrelated_stops: bool = False,
) -> dict[str, Any]:
    """Run until address/symbol is reached via a temporary software breakpoint."""
    parsed = _parse_address_or_symbol(address_or_symbol)
    if parsed is None:
        return _error(ValueError("address_or_symbol is required"))

    def action() -> dict[str, Any]:
        client = _require_client()
        target_address = _try_resolve_address(parsed)
        try:
            client.clear_debug_events()
        except Exception:
            pass
        client.set_breakpoint(
            parsed,
            bp_type=StandardBreakpointType.SingleShotInt3,
            singleshoot=True,
        )
        breakpoint_snapshot = _snapshot_breakpoints(client)
        client.go()
        deadline = time.monotonic() + max(0.1, float(timeout))
        unrelated_stops: list[dict[str, Any]] = []
        safe_max_unrelated_stops = max(0, int(max_unrelated_stops))
        wait_result: dict[str, Any] = {
            "matched": False,
            "timed_out": True,
            "expected_running": False,
            "is_running": True,
            "elapsed_ms": 0,
        }
        reached = False

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                wait_result = _wait_for_running_state(
                    expect_running=False,
                    timeout=0,
                    clear_stale_events=False,
                    include_events=True,
                )
                break

            wait_result = _wait_for_running_state(
                expect_running=False,
                timeout=max(0.1, remaining),
                clear_stale_events=False,
                include_events=True,
            )
            ip_value = wait_result.get("instruction_pointer_value")
            if isinstance(ip_value, int):
                snapshot_match = breakpoint_snapshot.get(ip_value, [])
                if snapshot_match:
                    wait_result = _apply_breakpoint_inference(
                        wait_result,
                        snapshot_match,
                        source="breakpoint_snapshot",
                    )
            reached = _did_hit_target(wait_result, target_address)
            if reached and wait_result.get("stop_reason") in ("unknown", "paused", None):
                target_match: list[dict[str, Any]] = []
                if isinstance(ip_value, int):
                    target_match = breakpoint_snapshot.get(ip_value, [])
                if not target_match and isinstance(target_address, int) and isinstance(ip_value, int) and ip_value == target_address:
                    target_match = [
                        {
                            "addr": target_address,
                            "type": int(BreakpointType.BpNormal.value),
                            "name": f"run_to_0x{target_address:X}",
                            "mod": "",
                            "detail": "software",
                        }
                    ]
                if target_match:
                    wait_result = _apply_breakpoint_inference(
                        wait_result,
                        target_match,
                        source="run_to_target_match",
                    )
            if reached:
                break
            if not bool(wait_result.get("matched")) or bool(wait_result.get("timed_out")):
                break
            if not continue_on_unrelated_stop:
                break

            unrelated_stops.append(_compact_stop_summary(wait_result))
            if len(unrelated_stops) >= safe_max_unrelated_stops:
                wait_result = dict(wait_result)
                wait_result["max_unrelated_stops_reached"] = True
                break

            breakpoint_snapshot = _snapshot_breakpoints(client)
            client.go()

        temporary_breakpoint_cleared = False
        if bool(wait_result.get("timed_out")) and clear_on_timeout:
            try:
                temporary_breakpoint_cleared = bool(client.clear_breakpoint(parsed))
            except Exception:
                temporary_breakpoint_cleared = False

        payload: dict[str, Any] = {
            "target": parsed,
            "target_address": f"0x{target_address:X}" if isinstance(target_address, int) else None,
            "reached": reached,
            "temporary_breakpoint_cleared": temporary_breakpoint_cleared,
            "unrelated_stop_count": len(unrelated_stops),
        }
        if include_unrelated_stops and unrelated_stops:
            payload["unrelated_stops"] = unrelated_stops
        payload.update(wait_result)
        return payload

    return _run(action)


@mcp.tool()
def wait_until_stopped(
    timeout: int = 10,
    detailed: bool = False,
    include_events: bool = True,
    clear_stale_events: bool = False,
    pause_on_timeout: bool = False,
) -> dict[str, Any]:
    """Wait until target stops (breakpoint, pause, exception, etc.)."""
    def action() -> bool | dict[str, Any]:
        result = _wait_for_running_state(
            expect_running=False,
            timeout=timeout,
            clear_stale_events=clear_stale_events,
            include_events=include_events,
            pause_on_timeout=pause_on_timeout,
        )
        if detailed:
            return result
        return bool(result.get("matched"))

    return _run(action)


@mcp.tool()
def wait_until_running(timeout: int = 10, detailed: bool = False) -> dict[str, Any]:
    """Wait until target enters running state."""
    def action() -> bool | dict[str, Any]:
        result = _wait_for_running_state(
            expect_running=True,
            timeout=timeout,
            clear_stale_events=False,
            include_events=False,
        )
        if detailed:
            return result
        return bool(result.get("matched"))

    return _run(action)


def _try_resolve_address(value: int | str) -> int | None:
    if isinstance(value, int):
        return value
    text = value.strip()
    if not text:
        return None
    try:
        return _parse_int(text, allow_expression=True)
    except Exception:
        return None


def _wait_for_running_state(
    expect_running: bool,
    timeout: int,
    *,
    clear_stale_events: bool,
    include_events: bool,
    pause_on_timeout: bool = False,
) -> dict[str, Any]:
    client = _require_client()
    if clear_stale_events and not expect_running:
        try:
            client.clear_debug_events()
        except Exception:
            pass

    start = time.monotonic()
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
            payload: dict[str, Any] = {
                "matched": True,
                "timed_out": False,
                "expected_running": expect_running,
                "is_running": running,
                "elapsed_ms": int((time.monotonic() - start) * 1000),
            }
            if expect_running:
                payload["running_observed"] = True
                payload["transient_running"] = False
            if not expect_running:
                ip: int | None = None
                try:
                    ip = _read_first_register(_require_client(), ("cip", "rip", "eip"))
                except Exception:
                    ip = None
                payload.update(
                    _collect_stop_details(
                        _require_client(),
                        include_events=include_events,
                        instruction_pointer_value=ip,
                    )
                )
                try:
                    if ip is None:
                        ip = _read_first_register(_require_client(), ("cip", "rip", "eip"))
                    payload["instruction_pointer"] = f"0x{ip:X}"
                    payload["instruction_pointer_value"] = ip
                    payload["instruction"] = _require_client().disassemble_at(ip)
                except Exception:
                    payload["instruction"] = None
            return payload
        time.sleep(sleep_interval)

    forced_pause = False
    if pause_on_timeout and not expect_running:
        try:
            forced_pause = bool(_require_client().pause())
        except Exception:
            forced_pause = False

    try:
        final_running = bool(_require_client().is_running())
    except Exception:
        final_running = True

    matched = final_running == expect_running
    payload = {
        "matched": matched,
        "timed_out": not matched,
        "expected_running": expect_running,
        "is_running": final_running,
        "elapsed_ms": int((time.monotonic() - start) * 1000),
        "forced_pause": forced_pause,
    }
    if expect_running:
        payload["running_observed"] = False
        payload["transient_running"] = False
    if expect_running and not final_running:
        ip = None
        try:
            ip = _read_first_register(_require_client(), ("cip", "rip", "eip"))
        except Exception:
            ip = None
        drained_events = _drain_debug_events(_require_client())
        events_since_resume = _events_since_last_resume(drained_events)
        saw_resume_event = any(
            item.event_type == EventType.EVENT_RESUME_DEBUG for item in drained_events
        )
        transient_stop = _build_stop_details_from_events(
            _require_client(),
            events_since_resume,
            include_events=include_events,
            instruction_pointer_value=ip,
        )
        inferred_stop = transient_stop.get("stop_reason") not in (None, "unknown")
        has_post_resume_activity = len(events_since_resume) > 1
        if saw_resume_event and (has_post_resume_activity or inferred_stop):
            payload.update(transient_stop)
            payload["matched"] = True
            payload["timed_out"] = False
            payload["running_observed"] = True
            payload["transient_running"] = True
            if ip is not None:
                try:
                    payload["instruction_pointer"] = f"0x{ip:X}"
                    payload["instruction_pointer_value"] = ip
                    payload["instruction"] = _require_client().disassemble_at(ip)
                except Exception:
                    payload["instruction"] = None
            return payload
        if saw_resume_event:
            payload["saw_resume_event"] = True

    if not expect_running:
        ip = None
        try:
            ip = _read_first_register(_require_client(), ("cip", "rip", "eip"))
        except Exception:
            ip = None
        payload.update(
            _collect_stop_details(
                _require_client(),
                include_events=include_events,
                instruction_pointer_value=ip,
            )
        )
        try:
            if ip is None:
                ip = _read_first_register(_require_client(), ("cip", "rip", "eip"))
            payload["instruction_pointer"] = f"0x{ip:X}"
            payload["instruction_pointer_value"] = ip
            payload["instruction"] = _require_client().disassemble_at(ip)
        except Exception:
            payload["instruction"] = None
    return payload


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
def get_latest_event(pop: bool = True) -> dict[str, Any]:
    """Get the latest debug event from x64dbg's event queue."""
    def action() -> dict[str, Any]:
        client = _require_client()
        event = client.get_latest_debug_event() if pop else client.peek_latest_debug_event()
        if event is None:
            return {"event": None}
        return {"event": _event_to_payload(event), "popped": bool(pop)}

    return _run(action)


@mcp.tool()
def drain_events(max_events: int = 32, clear_before: bool = False) -> dict[str, Any]:
    """Drain recent debug events from queue for post-stop diagnosis."""
    safe_limit = max(1, min(int(max_events), 512))

    def action() -> dict[str, Any]:
        client = _require_client()
        if clear_before:
            client.clear_debug_events()
            return {"events": [], "drained": 0, "cleared_before": True}

        events = _drain_debug_events(client, max_events=safe_limit)
        return {
            "events": [_event_to_payload(item) for item in events],
            "drained": len(events),
            "max_events": safe_limit,
            "cleared_before": False,
        }

    return _run(action)


@mcp.tool()
def wait_for_event(event_type: str, timeout: int = 5) -> dict[str, Any]:
    """Wait for a specific debug event type (e.g. EVENT_BREAKPOINT)."""
    parsed_type = _parse_event_type(event_type)
    safe_timeout = max(1, int(timeout))

    def action() -> dict[str, Any]:
        event = _require_client().wait_for_debug_event(parsed_type, timeout=safe_timeout)
        return {
            "event_type": parsed_type.value,
            "timeout": safe_timeout,
            "received": event is not None,
            "event": _event_to_payload(event) if event is not None else None,
        }

    return _run(action)


@mcp.tool()
def write_text_memory(
    address: int | str,
    text: str,
    encoding: str = "utf-8",
    append_null: bool = False,
) -> dict[str, Any]:
    """Write text bytes to memory (supports ascii/utf-8/utf-16le)."""
    parsed_address = _parse_int(address, allow_expression=True)
    data, normalized_encoding = _encode_text_bytes(text, encoding, append_null)
    _validate_rw_size(len(data))

    def action() -> dict[str, Any]:
        updated = _require_client().write_memory(parsed_address, data)
        return {
            "address": f"0x{parsed_address:X}",
            "updated": updated,
            "written_size": len(data),
            "encoding": normalized_encoding,
            "append_null": append_null,
        }

    return _run(action)


@mcp.tool()
def inject_string_and_continue(
    buffer_address: int | str,
    text: str,
    continue_at: int | str,
    encoding: str = "ascii",
    append_null: bool = True,
) -> dict[str, Any]:
    """Write string to memory and set IP to continue address (useful for scanf/read bypass)."""
    parsed_buffer = _parse_int(buffer_address, allow_expression=True)
    parsed_continue = _parse_int(continue_at, allow_expression=True)
    data, normalized_encoding = _encode_text_bytes(text, encoding, append_null)
    _validate_rw_size(len(data))

    def action() -> dict[str, Any]:
        client = _require_client()
        old_ip = _read_first_register(client, ("cip", "rip", "eip"))
        write_ok = client.write_memory(parsed_buffer, data)
        ip_register = _set_first_register(client, ("cip", "rip", "eip"), parsed_continue)
        return {
            "buffer_address": f"0x{parsed_buffer:X}",
            "continue_at": f"0x{parsed_continue:X}",
            "write_ok": write_ok,
            "written_size": len(data),
            "encoding": normalized_encoding,
            "append_null": append_null,
            "previous_ip": f"0x{old_ip:X}",
            "ip_register": ip_register,
        }

    return _run(action)


@mcp.tool()
def find_memory_pattern(
    pattern: str,
    pattern_type: str = "hex",
    max_hits: int = 32,
    max_pages: int = 256,
    module_filter: str = "",
    case_insensitive: bool = False,
    scan_chunk_size: int = 0x4000,
    max_page_scan_size: int = 0x200000,
) -> dict[str, Any]:
    """Scan memory pages for a hex/ascii/utf16le pattern."""
    needle, selected_type = _parse_pattern_bytes(pattern, pattern_type)
    if case_insensitive and selected_type != "ascii":
        return _error(ValueError("case_insensitive is only supported for pattern_type=ascii"))

    safe_max_hits = max(1, int(max_hits))
    safe_max_pages = max(1, int(max_pages))
    safe_chunk_size = max(1, min(int(scan_chunk_size), MAX_MEMORY_RW))
    safe_max_page_scan_size = max(1, int(max_page_scan_size))
    module_filter_text = module_filter.strip().lower()

    def action() -> dict[str, Any]:
        client = _require_client()
        pages = client.memmap()[:safe_max_pages]
        hits: list[dict[str, Any]] = []
        seen_hits: set[int] = set()
        scanned_pages = 0
        scanned_bytes = 0
        unreadable_pages = 0
        skipped_pages = 0
        needle_len = len(needle)
        match_needle = needle.lower() if case_insensitive else needle

        for page in pages:
            if len(hits) >= safe_max_hits:
                break
            page_base = int(getattr(page, "base_address", 0))
            page_size = int(getattr(page, "region_size", 0))
            page_info = str(getattr(page, "info", ""))
            if page_size <= 0:
                skipped_pages += 1
                continue
            if module_filter_text and module_filter_text not in page_info.lower():
                skipped_pages += 1
                continue

            scanned_pages += 1
            scan_limit = min(page_size, safe_max_page_scan_size)
            offset = 0
            overlap = max(0, needle_len - 1)
            tail = b""

            while offset < scan_limit and len(hits) < safe_max_hits:
                read_size = min(safe_chunk_size, scan_limit - offset)
                read_address = page_base + offset
                try:
                    chunk = client.read_memory(read_address, read_size)
                except Exception:
                    unreadable_pages += 1
                    break
                if not chunk:
                    break

                scanned_bytes += len(chunk)
                window = tail + chunk
                search_window = window.lower() if case_insensitive else window
                search_from = 0
                while True:
                    index = search_window.find(match_needle, search_from)
                    if index < 0:
                        break
                    hit_address = read_address - len(tail) + index
                    if hit_address not in seen_hits:
                        seen_hits.add(hit_address)
                        hits.append(
                            {
                                "address": f"0x{hit_address:X}",
                                "page_base": f"0x{page_base:X}",
                                "page_info": page_info,
                            }
                        )
                        if len(hits) >= safe_max_hits:
                            break
                    search_from = index + 1

                if overlap > 0 and len(window) > overlap:
                    tail = window[-overlap:]
                else:
                    tail = window
                offset += len(chunk)

        return {
            "pattern_type": selected_type,
            "pattern_size": needle_len,
            "hit_count": len(hits),
            "max_hits": safe_max_hits,
            "max_pages": safe_max_pages,
            "scanned_pages": scanned_pages,
            "skipped_pages": skipped_pages,
            "unreadable_pages": unreadable_pages,
            "scanned_bytes": scanned_bytes,
            "hits": hits,
        }

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
def disassemble(address: int | str, count: int = 1) -> dict[str, Any]:
    """Disassemble one or more instructions at an address."""
    parsed_address = _parse_int(address, allow_expression=True)
    safe_count = max(1, min(int(count), 256))

    def action() -> dict[str, Any]:
        client = _require_client()
        if safe_count == 1:
            return client.disassemble_at(parsed_address)

        instructions: list[dict[str, Any]] = []
        current = parsed_address
        for _ in range(safe_count):
            item = client.disassemble_at(current)
            if item is None:
                break
            entry = _to_jsonable(item)
            if isinstance(entry, dict):
                entry["address"] = f"0x{current:X}"
            instructions.append(entry)
            instr_size = getattr(item, "instr_size", 0)
            if not isinstance(instr_size, int) or instr_size <= 0:
                break
            current += instr_size

        return {
            "address": f"0x{parsed_address:X}",
            "count": safe_count,
            "decoded": len(instructions),
            "truncated": len(instructions) < safe_count,
            "instructions": instructions,
        }

    return _run(action)


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
def profile_pe(file_path: str) -> dict[str, Any]:
    """Statically profile a PE for VMP/VMP-like/generic packing indicators."""
    return _run(lambda: _profile_pe_file_impl(file_path))


@mcp.tool()
def scan_suspicious_pages(
    module_filter: str = "",
    max_entries: int = 64,
    executable_only: bool = True,
    include_image: bool = True,
    include_private: bool = True,
    include_mapped: bool = False,
    min_size: int = 0x1000,
) -> dict[str, Any]:
    """Scan runtime memory for executable/private/RWX pages useful for unpacking and malware analysis."""
    safe_max_entries = max(1, min(int(max_entries), 512))
    safe_min_size = max(0x1000, int(min_size))
    module_filter_text = module_filter.strip().lower()

    def action() -> dict[str, Any]:
        client = _require_client()
        current_ip: int | None = None
        current_ip_page = None
        current_symbol = None
        try:
            current_ip = _read_first_register(client, ("cip", "rip", "eip"))
            current_ip_page = client.virt_query(current_ip)
            current_symbol = client.get_symbol_at(current_ip)
        except Exception:
            current_ip = None

        matches: list[dict[str, Any]] = []
        counts = {"image": 0, "private": 0, "mapped": 0}
        for page in client.memmap():
            payload = _page_payload(page)
            if payload["region_size"] < safe_min_size:
                continue
            if executable_only and not payload["is_executable"]:
                continue
            page_type = payload["type_text"]
            if page_type == "IMAGE" and not include_image:
                continue
            if page_type == "PRIVATE" and not include_private:
                continue
            if page_type == "MAPPED" and not include_mapped:
                continue
            if module_filter_text and module_filter_text not in str(payload["info"]).lower():
                continue

            score, reasons = _score_page_suspicion(payload, current_ip=current_ip)
            payload["suspicion_score"] = score
            payload["suspicion_reasons"] = reasons
            if isinstance(current_ip, int):
                base_address = payload["base_address_value"]
                end_address = base_address + payload["region_size"]
                if base_address <= current_ip < end_address:
                    payload["current_ip_offset"] = current_ip - base_address
            matches.append(payload)
            if page_type.lower() in counts:
                counts[page_type.lower()] += 1

        matches.sort(
            key=lambda item: (
                int(item.get("suspicion_score", 0)),
                int(item.get("is_writable", False)),
                int(item.get("region_size", 0)),
            ),
            reverse=True,
        )
        top_matches = matches[:safe_max_entries]
        response: dict[str, Any] = {
            "total_candidates": len(matches),
            "returned": len(top_matches),
            "counts": counts,
            "pages": top_matches,
        }
        if isinstance(current_ip, int):
            response["current_ip"] = f"0x{current_ip:X}"
        if current_ip_page is not None:
            response["current_ip_page"] = _page_payload(current_ip_page)
        if current_symbol is not None:
            response["current_symbol"] = _to_jsonable(current_symbol)
        main_pages = _main_module_pages(client)
        if main_pages:
            response["main_module_base"] = f"0x{int(getattr(main_pages[0], 'allocation_base', 0)):X}"
            response["main_module_page_count"] = len(main_pages)
        return response

    return _run(action)


@mcp.tool()
def dump_memory_regions(
    output_dir: str,
    module_filter: str = "",
    executable_only: bool = True,
    include_image: bool = False,
    include_private: bool = True,
    include_mapped: bool = False,
    include_current_ip_page: bool = True,
    max_regions: int = 16,
    max_region_size: int = 0x400000,
) -> dict[str, Any]:
    """Dump selected runtime memory regions to disk for unpacking and malware analysis."""
    out_dir = Path(output_dir).expanduser()
    safe_max_regions = max(1, min(int(max_regions), 128))
    safe_max_region_size = max(0x1000, int(max_region_size))
    module_filter_text = module_filter.strip().lower()

    def action() -> dict[str, Any]:
        client = _require_client()
        out_dir.mkdir(parents=True, exist_ok=True)
        current_ip: int | None = None
        if include_current_ip_page:
            try:
                current_ip = _read_first_register(client, ("cip", "rip", "eip"))
            except Exception:
                current_ip = None

        selected: list[dict[str, Any]] = []
        seen_pages: set[int] = set()
        for page in client.memmap():
            payload = _page_payload(page)
            base_address = payload["base_address_value"]
            if base_address in seen_pages:
                continue
            if payload["region_size"] <= 0 or payload["region_size"] > safe_max_region_size:
                continue
            if executable_only and not payload["is_executable"]:
                continue
            page_type = payload["type_text"]
            if page_type == "IMAGE" and not include_image:
                continue
            if page_type == "PRIVATE" and not include_private:
                continue
            if page_type == "MAPPED" and not include_mapped:
                continue
            if module_filter_text and module_filter_text not in str(payload["info"]).lower():
                continue
            score, reasons = _score_page_suspicion(payload, current_ip=current_ip)
            payload["suspicion_score"] = score
            payload["suspicion_reasons"] = reasons
            selected.append(payload)
            seen_pages.add(base_address)

        if include_current_ip_page and isinstance(current_ip, int):
            current_page = client.virt_query(current_ip)
            if current_page is not None:
                payload = _page_payload(current_page)
                base_address = payload["base_address_value"]
                if base_address not in seen_pages and 0 < payload["region_size"] <= safe_max_region_size:
                    score, reasons = _score_page_suspicion(payload, current_ip=current_ip)
                    payload["suspicion_score"] = score
                    payload["suspicion_reasons"] = reasons
                    payload["forced_include"] = True
                    selected.append(payload)
                    seen_pages.add(base_address)

        selected.sort(
            key=lambda item: (
                int(item.get("suspicion_score", 0)),
                int(item.get("region_size", 0)),
            ),
            reverse=True,
        )
        selected = selected[:safe_max_regions]

        dumped: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        for index, page in enumerate(selected):
            base_address = int(page["base_address_value"])
            try:
                data = _chunked_read_process_memory(client, base_address, int(page["region_size"]))
                if not data:
                    raise RuntimeError("empty dump")
                type_text = str(page["type_text"]).lower()
                protect_text = str(page["protect_text"]).replace("|", "-").lower()
                filename = f"{index:02d}_0x{base_address:X}_{type_text}_{protect_text}.bin"
                file_path = out_dir / filename
                file_path.write_bytes(data)
                dumped.append(
                    {
                        "file_path": str(file_path),
                        "size": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "page": page,
                    }
                )
            except Exception as exc:
                errors.append(
                    {
                        "base_address": f"0x{base_address:X}",
                        "error": str(exc),
                    }
                )

        manifest = {
            "output_dir": str(out_dir),
            "dumped_count": len(dumped),
            "error_count": len(errors),
            "regions": dumped,
            "errors": errors,
        }
        manifest_path = out_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        return {
            "output_dir": str(out_dir),
            "dumped_count": len(dumped),
            "error_count": len(errors),
            "manifest": str(manifest_path),
            "regions": dumped,
            "errors": errors,
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

    def action() -> dict[str, Any]:
        client = _require_client()
        updated = client.set_breakpoint(
            parsed,
            name=bp_name,
            bp_type=bp_kind,
            singleshoot=singleshot,
        )
        if updated:
            _remember_software_breakpoint(
                SoftwareBreakpointSpec(
                    target=parsed,
                    kind=bp_kind,
                    name=bp_name,
                    singleshot=singleshot,
                )
            )
        return {"set": updated}

    return _run(action)


@mcp.tool()
def clear_breakpoint(address_or_symbol: int | str | None = None) -> dict[str, Any]:
    """Clear one software breakpoint, or all software breakpoints if empty."""
    parsed = _parse_address_or_symbol(address_or_symbol)

    def action() -> dict[str, Any]:
        cleared = bool(_require_client().clear_breakpoint(parsed))
        if cleared:
            _forget_software_breakpoint(parsed)
        return {"cleared": cleared}

    return _run(action)


@mcp.tool()
def set_hardware_breakpoint(address_or_symbol: int | str, kind: str = "x", size: int = 1) -> dict[str, Any]:
    """Set hardware breakpoint. kind: r | w | x."""
    parsed = _parse_address_or_symbol(address_or_symbol)
    if parsed is None:
        return _error(ValueError("address_or_symbol is required"))
    parsed_kind = _parse_hw_kind(kind)
    safe_size = max(1, int(size))

    def action() -> dict[str, Any]:
        updated = _require_client().set_hardware_breakpoint(
            parsed,
            bp_type=parsed_kind,
            size=safe_size,
        )
        if updated:
            _remember_hardware_breakpoint(
                HardwareBreakpointSpec(
                    target=parsed,
                    kind=parsed_kind,
                    size=safe_size,
                )
            )
        return {"set": updated}

    return _run(action)


@mcp.tool()
def clear_hardware_breakpoint(address_or_symbol: int | str | None = None) -> dict[str, Any]:
    """Clear one hardware breakpoint, or all hardware breakpoints if empty."""
    parsed = _parse_address_or_symbol(address_or_symbol)

    def action() -> dict[str, Any]:
        cleared = bool(_require_client().clear_hardware_breakpoint(parsed))
        if cleared:
            _forget_hardware_breakpoint(parsed)
        return {"cleared": cleared}

    return _run(action)


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
    parsed_kind = _parse_mem_kind(kind)

    def action() -> dict[str, Any]:
        updated = _require_client().set_memory_breakpoint(
            parsed,
            bp_type=parsed_kind,
            singleshoot=singleshot,
        )
        if updated:
            _remember_memory_breakpoint(
                MemoryBreakpointSpec(
                    target=parsed,
                    kind=parsed_kind,
                    singleshot=singleshot,
                )
            )
        return {"set": updated}

    return _run(action)


@mcp.tool()
def clear_memory_breakpoint(address_or_symbol: int | str | None = None) -> dict[str, Any]:
    """Clear one memory breakpoint, or all memory breakpoints if empty."""
    parsed = _parse_address_or_symbol(address_or_symbol)

    def action() -> dict[str, Any]:
        cleared = bool(_require_client().clear_memory_breakpoint(parsed))
        if cleared:
            _forget_memory_breakpoint(parsed)
        return {"cleared": cleared}

    return _run(action)


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
