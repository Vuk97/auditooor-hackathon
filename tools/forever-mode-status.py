#!/usr/bin/env python3
"""forever-mode-status.py — observability for the forever-mode background system.

Read-only health check across the 5 background loops + watchdog. Aggregates
state from:
  - PID files written by /tmp/forever_watchdog.sh (one per loop) +
    /tmp/forever_watchdog.pid for the watchdog itself.
  - Log files at /tmp/forever_logs/<name>.log (last line = recent activity).
  - Iter directories that the worker loops emit:
      * overnight  → /tmp/llm_loop_v2/iter_NNN/
      * improvement→ /tmp/auto_improvement_v2/iter_NNN/
  - Queue/output files: /tmp/auto_improvement_v2/queue.md,
    /tmp/next_roadmap_consultations.md, /tmp/ready_to_dispatch.md,
    /tmp/llm_self_reflections.md.

Hard rule: this tool MUST NOT modify any pid file, log file, queue file,
or process. Pure observation only.

Usage:
    python3 tools/forever-mode-status.py            # human-readable
    python3 tools/forever-mode-status.py --json     # JSON to stdout
    python3 tools/forever-mode-status.py --watch    # 30s refresh until Ctrl-C

30/10 plan, Step 5 (Minimax brief).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ───────────────────────────────────────────────────────────── conventions ──

DEFAULT_LOG_DIR = Path("/tmp/forever_logs")
DEFAULT_WATCHDOG_PID = Path("/tmp/forever_watchdog.pid")

# Each loop's display name → (pid file, log file, iter root dir or None,
#                             "primary" queue file or None for staleness check)
LOOP_SPEC: dict[str, dict[str, Any]] = {
    "overnight": {
        "pid": "overnight.pid",
        "log": "overnight.log",
        "iter_root": "/tmp/llm_loop_v2",
        "queue": None,  # staleness measured from iter_root
    },
    "improvement": {
        "pid": "improvement.pid",
        "log": "improvement.log",
        "iter_root": "/tmp/auto_improvement_v2",
        "queue": "/tmp/auto_improvement_v2/queue.md",
    },
    "next_roadmap": {
        "pid": "next_roadmap.pid",
        "log": "next_roadmap.log",
        "iter_root": None,
        "queue": "/tmp/next_roadmap_consultations.md",
    },
    "self_reflection": {
        "pid": "self_reflection.pid",
        "log": "self_reflection.log",
        "iter_root": None,
        "queue": "/tmp/llm_self_reflections.md",
    },
    "dispatch_ready": {
        "pid": "dispatch_ready.pid",
        "log": "dispatch_ready.log",
        "iter_root": None,
        "queue": "/tmp/ready_to_dispatch.md",
    },
}

# Queues block — rolled-up view for the user.
QUEUE_SPEC: dict[str, dict[str, Any]] = {
    "auto_improvement": {
        "path": "/tmp/auto_improvement_v2/queue.md",
        "iter_root": "/tmp/auto_improvement_v2",
    },
    "next_roadmap_consultations": {
        "path": "/tmp/next_roadmap_consultations.md",
        "iter_root": None,
    },
    "ready_to_dispatch": {
        "path": "/tmp/ready_to_dispatch.md",
        "iter_root": None,
    },
}

ITER_DIR_RE = re.compile(r"^iter_(\d+)$")

# Health thresholds (seconds).
QUEUE_STALE_SEC = 60 * 60          # 1hr — anything older = stale.
ITER_STALE_SEC = 60 * 60           # 1hr — last iter older = stale.

# ───────────────────────────────────────────────────────────────── helpers ──


@dataclass
class Snapshot:
    watchdog: dict[str, Any] = field(default_factory=dict)
    loops: dict[str, dict[str, Any]] = field(default_factory=dict)
    queues: dict[str, dict[str, Any]] = field(default_factory=dict)
    health: str = "GREEN"
    last_check: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "watchdog": self.watchdog,
            "loops": self.loops,
            "queues": self.queues,
            "health": self.health,
            "last_check": self.last_check,
        }


def _read_pid(pid_path: Path) -> int | None:
    """Read an integer pid from a file, tolerating whitespace. None if missing
    or unparseable."""
    try:
        raw = pid_path.read_text(encoding="utf-8", errors="replace").strip()
    except (FileNotFoundError, IsADirectoryError, PermissionError):
        return None
    if not raw:
        return None
    try:
        return int(raw.splitlines()[0].strip())
    except ValueError:
        return None


def _process_alive(pid: int | None) -> bool:
    """True iff pid > 0 and `kill -0` succeeds. Stdlib only, POSIX."""
    if pid is None or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Process exists but we lack signal permission — still alive.
        return True
    except OSError:
        return False
    return True


def _process_ppid(pid: int | None) -> int | None:
    """Look up parent pid via /proc on Linux, `ps` fallback elsewhere.
    Returns None on failure. Stdlib-only — uses subprocess.run on `ps`."""
    if pid is None or pid <= 0:
        return None
    proc_status = Path(f"/proc/{pid}/status")
    if proc_status.exists():
        try:
            for line in proc_status.read_text().splitlines():
                if line.startswith("PPid:"):
                    return int(line.split()[1])
        except (OSError, ValueError):
            return None
        return None
    # macOS / BSD fallback.
    try:
        import subprocess
        out = subprocess.run(
            ["ps", "-p", str(pid), "-o", "ppid="],
            capture_output=True, text=True, timeout=5,
        )
        if out.returncode == 0 and out.stdout.strip():
            return int(out.stdout.strip().split()[0])
    except (OSError, ValueError):
        return None
    except Exception:  # noqa: BLE001 — subprocess raises a wide range
        return None
    return None


def _last_log_line(log_path: Path, *, max_chars: int = 240) -> str:
    """Last non-empty line of `log_path`. Empty string if missing. Reads only
    the tail to stay cheap on big logs."""
    try:
        size = log_path.stat().st_size
    except (FileNotFoundError, OSError):
        return ""
    if size == 0:
        return ""
    # Read up to the final 4 KiB — enough for any single log line we emit.
    chunk = 4096
    try:
        with log_path.open("rb") as fh:
            if size > chunk:
                fh.seek(-chunk, os.SEEK_END)
            data = fh.read()
    except OSError:
        return ""
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return ""
    for line in reversed(text.splitlines()):
        s = line.strip()
        if s:
            return s[:max_chars]
    return ""


def _latest_iter_dir(iter_root: Path) -> Path | None:
    """Find the most-recently-modified iter_NNN/ subdir. None if the root
    doesn't exist or has no matching subdirs.

    Uses mtime, not numeric suffix, because the forever loops wrap: the
    inner loop counts up to iter_060 then the outer wrapper sleeps and
    restarts at iter_001. A pure numeric sort would keep reporting the
    stale iter_060 from the previous cycle as "latest" forever. mtime
    correctly picks the freshest dir regardless of cycle.

    Tie-breaker on equal mtime: highest numeric suffix wins (deterministic
    across filesystems that round mtime to whole seconds)."""
    if not iter_root.exists() or not iter_root.is_dir():
        return None
    best: tuple[float, int, Path] | None = None
    try:
        for child in iter_root.iterdir():
            if not child.is_dir():
                continue
            m = ITER_DIR_RE.match(child.name)
            if not m:
                continue
            try:
                mtime = child.stat().st_mtime
            except OSError:
                continue
            n = int(m.group(1))
            key = (mtime, n)
            if best is None or key > (best[0], best[1]):
                best = (mtime, n, child)
    except OSError:
        return None
    return best[2] if best else None


def _age_sec(path: Path | None, *, now: float | None = None) -> int | None:
    """Seconds since `path`'s mtime. None if no path / missing."""
    if path is None:
        return None
    try:
        mtime = path.stat().st_mtime
    except (FileNotFoundError, OSError):
        return None
    ref = time.time() if now is None else now
    return max(0, int(ref - mtime))


def _file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except (FileNotFoundError, OSError):
        return 0


def _file_line_count(path: Path) -> int:
    """Number of newlines in `path`. 0 if missing."""
    try:
        n = 0
        with path.open("rb") as fh:
            for _ in fh:
                n += 1
        return n
    except (FileNotFoundError, OSError):
        return 0


def _last_consultation_header(path: Path) -> str:
    """Pull the most recent `## ...` header from a markdown consultation log.
    Empty string if none."""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            tail = fh.readlines()[-200:]
    except (FileNotFoundError, OSError):
        return ""
    for line in reversed(tail):
        s = line.strip()
        if s.startswith("## "):
            return s[3:].strip()[:160]
    return ""


# ──────────────────────────────────────────────────────────────── snapshot ──


def _resolve_path(base: Path | None, p: str) -> Path:
    """If `base` is set, swap a `/tmp/...` absolute path into the sandbox.
    Used by tests to redirect the entire forever-mode tree under tmp."""
    if base is None:
        return Path(p)
    if p.startswith("/tmp/"):
        return base / p[len("/tmp/"):]
    return Path(p)


def collect(
    log_dir: Path = DEFAULT_LOG_DIR,
    watchdog_pid_path: Path = DEFAULT_WATCHDOG_PID,
    *,
    now: float | None = None,
    tmp_base: Path | None = None,
) -> Snapshot:
    """Pure observation — read pid/log/queue files, return a Snapshot.

    `tmp_base`: if set, all `/tmp/...` path constants in LOOP_SPEC /
    QUEUE_SPEC are rerooted under this directory. Tests use this to stage
    a hermetic sandbox without touching the real filesystem state.
    """
    now = time.time() if now is None else now
    snap = Snapshot(last_check=datetime.fromtimestamp(now, tz=timezone.utc).isoformat())

    # Watchdog block.
    wd_pid = _read_pid(watchdog_pid_path)
    wd_alive = _process_alive(wd_pid)
    snap.watchdog = {
        "alive": wd_alive,
        "pid": wd_pid if wd_pid is not None else 0,
        "ppid": _process_ppid(wd_pid) if wd_alive else 0,
        "last_log_line": "",
    }
    # Watchdog log: the watchdog itself logs to its stdout (under tmux/nohup).
    # Best-effort: we look at any /tmp/forever_watchdog*.log if present.
    wd_log_candidates = [
        _resolve_path(tmp_base, "/tmp/forever_watchdog.log"),
        _resolve_path(tmp_base, "/tmp/forever_watchdog_v2.log"),
    ]
    for cand in wd_log_candidates:
        line = _last_log_line(cand)
        if line:
            snap.watchdog["last_log_line"] = line
            break

    # Per-loop block.
    dead_loops = 0
    for name, spec in LOOP_SPEC.items():
        pid_path = log_dir / spec["pid"]
        log_path = log_dir / spec["log"]
        pid = _read_pid(pid_path)
        alive = _process_alive(pid)
        if not alive:
            dead_loops += 1
        iter_root = (_resolve_path(tmp_base, spec["iter_root"])
                     if spec["iter_root"] else None)
        last_iter = _latest_iter_dir(iter_root) if iter_root else None
        snap.loops[name] = {
            "alive": alive,
            "pid": pid if pid is not None else 0,
            "last_iter_dir": str(last_iter) if last_iter else "",
            "last_iter_age_sec": _age_sec(last_iter, now=now) or 0,
            "last_log_line": _last_log_line(log_path),
        }

    # Queues block.
    stale_queues = 0
    for name, spec in QUEUE_SPEC.items():
        q_path = _resolve_path(tmp_base, spec["path"])
        size_bytes = _file_size(q_path)
        size_lines = _file_line_count(q_path)
        age = _age_sec(q_path, now=now)
        info: dict[str, Any] = {
            "size_bytes": size_bytes,
            "size_lines": size_lines,
            "age_sec": age if age is not None else -1,
        }
        # Per-queue specific extras.
        if spec.get("iter_root"):
            iter_root = _resolve_path(tmp_base, spec["iter_root"])
            last = _latest_iter_dir(iter_root)
            if last:
                m = ITER_DIR_RE.match(last.name)
                info["last_iter"] = int(m.group(1)) if m else 0
            else:
                info["last_iter"] = 0
        if name == "next_roadmap_consultations":
            info["last_consultation"] = _last_consultation_header(q_path)
        if age is not None and age > QUEUE_STALE_SEC:
            stale_queues += 1
        elif age is None:
            # Missing queue file = stale (worst case).
            stale_queues += 1
        snap.queues[name] = info

    # Health rollup.
    if not wd_alive or dead_loops >= 2:
        snap.health = "RED"
    elif dead_loops == 1 or stale_queues >= 1:
        snap.health = "YELLOW"
    else:
        snap.health = "GREEN"

    return snap


# ──────────────────────────────────────────────────────────────── render ──


def _fmt_age(sec: int) -> str:
    if sec < 0:
        return "n/a"
    if sec < 60:
        return f"{sec}s"
    if sec < 3600:
        return f"{sec // 60}m{sec % 60:02d}s"
    return f"{sec // 3600}h{(sec % 3600) // 60:02d}m"


def render_human(snap: Snapshot) -> str:
    out: list[str] = []
    color = {"GREEN": "GREEN", "YELLOW": "YELLOW", "RED": "RED"}[snap.health]
    out.append(f"forever-mode status [{color}]  ({snap.last_check})")
    out.append("=" * 72)

    wd = snap.watchdog
    out.append(
        "watchdog        : "
        f"alive={wd['alive']!s:5}  pid={wd['pid']:<6}  ppid={wd['ppid']}"
    )
    if wd.get("last_log_line"):
        out.append(f"  log: {wd['last_log_line']}")
    out.append("")
    out.append("loops:")
    for name, info in snap.loops.items():
        line = (
            f"  {name:<16} alive={info['alive']!s:5}  "
            f"pid={info['pid']:<6}  "
            f"last-iter={_fmt_age(info['last_iter_age_sec'])}"
        )
        if info["last_iter_dir"]:
            line += f"  ({Path(info['last_iter_dir']).name})"
        out.append(line)
        if info.get("last_log_line"):
            out.append(f"      log: {info['last_log_line'][:140]}")
    out.append("")
    out.append("queues:")
    for name, info in snap.queues.items():
        line = (
            f"  {name:<28} bytes={info['size_bytes']:<8}  "
            f"lines={info['size_lines']:<6}  "
            f"age={_fmt_age(info['age_sec'])}"
        )
        if "last_iter" in info:
            line += f"  iter={info['last_iter']}"
        out.append(line)
        if info.get("last_consultation"):
            out.append(f"      last: {info['last_consultation'][:120]}")
    out.append("")
    out.append(f"HEALTH: {snap.health}")
    return "\n".join(out)


# ───────────────────────────────────────────────────────────── entrypoint ──


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="forever-mode-status",
        description=("Observability for the forever-mode background loops "
                     "+ watchdog. Read-only. Emits human-readable text "
                     "(default) or JSON (--json)."),
    )
    p.add_argument("--json", action="store_true",
                   help="Emit a JSON snapshot to stdout.")
    p.add_argument("--watch", action="store_true",
                   help="Refresh every 30s until interrupted.")
    p.add_argument("--log-dir", default=str(DEFAULT_LOG_DIR),
                   help=f"Directory of *.pid/*.log per loop "
                        f"(default: {DEFAULT_LOG_DIR}).")
    p.add_argument("--watchdog-pid", default=str(DEFAULT_WATCHDOG_PID),
                   help=f"Watchdog pid file "
                        f"(default: {DEFAULT_WATCHDOG_PID}).")
    p.add_argument("--interval", type=int, default=30,
                   help="--watch refresh interval (seconds, default 30).")
    args = p.parse_args(argv)

    log_dir = Path(args.log_dir)
    wd_pid = Path(args.watchdog_pid)

    def render_once() -> Snapshot:
        snap = collect(log_dir, wd_pid)
        if args.json:
            sys.stdout.write(json.dumps(snap.to_dict(), indent=2) + "\n")
        else:
            sys.stdout.write(render_human(snap) + "\n")
        sys.stdout.flush()
        return snap

    if not args.watch:
        snap = render_once()
        # Exit codes: 0 GREEN, 1 YELLOW, 2 RED — useful for CI/cron alerting.
        return {"GREEN": 0, "YELLOW": 1, "RED": 2}[snap.health]

    # Watch loop. Ctrl-C exits cleanly.
    try:
        while True:
            # ANSI clear so successive renders overwrite the prior one.
            if not args.json:
                sys.stdout.write("\x1b[2J\x1b[H")
            render_once()
            time.sleep(max(1, args.interval))
    except KeyboardInterrupt:
        sys.stdout.write("\n[forever-mode-status] interrupted\n")
        return 0


if __name__ == "__main__":
    sys.exit(main())
