#!/usr/bin/env python3
"""audit-heavy-lock - serialize the MEMORY-HEAVY audit make targets per workspace so
concurrent runs can never STACK and OOM the machine.

Why (operator machine OOM-killed twice, 2026-07-07): the 5-min audit loop launched
`make audit-depth` / `make audit-complete` in the BACKGROUND (fire-and-forget) while
a prior run was still going. Each heavy run spawns crytic-compile + slither over the
full contracts tree + an 8-worker multiprocessing pool (+ go-dataflow, known 543MB
slice). Cron fires every 5 min; a heavy run takes >5 min; so 3-4 stack concurrently
-> RAM exhausted -> swap thrash -> machine dies -> user force-restarts (losing all
in-flight work). This wraps a heavy command in a per-(workspace,target) lock: a
SECOND heavy run REFUSES to start while a live one holds the lock (exit 3), capping
concurrent heavy memory at one run. Stale locks (dead pid, or older than the TTL) are
reclaimed so a crashed/killed run never wedges the loop forever.

Usage:
  audit-heavy-lock.py run <ws> <target> [--ttl N] -- <cmd...>   # acquire, run, release
  audit-heavy-lock.py status <ws>                               # list live/stale locks
  audit-heavy-lock.py clear <ws> [target]                       # force-clear (orphans)
Exit: 0 ok | 3 refused (a live heavy run holds the lock) | 1 usage/error | <cmd rc>.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

DEFAULT_TTL = 1200  # seconds; a heavy run older than this is presumed dead/stuck


def _lock_path(ws: Path, target: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in target)
    return ws / ".auditooor" / f".heavy_lock_{safe}.json"


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, not ours


def _read_lock(p: Path):
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return None


def _is_live(lock: dict, ttl: int, now: float) -> bool:
    if not isinstance(lock, dict):
        return False
    pid = int(lock.get("pid", 0) or 0)
    ts = float(lock.get("ts", 0) or 0)
    return _pid_alive(pid) and (now - ts) < ttl


def cmd_status(ws: Path, now: float) -> int:
    d = ws / ".auditooor"
    any_live = False
    if d.is_dir():
        for p in sorted(d.glob(".heavy_lock_*.json")):
            lock = _read_lock(p) or {}
            live = _is_live(lock, int(lock.get("ttl", DEFAULT_TTL)), now)
            any_live = any_live or live
            age = int(now - float(lock.get("ts", now)))
            print(f"{'LIVE ' if live else 'STALE'} {p.name} pid={lock.get('pid')} "
                  f"target={lock.get('target')} age={age}s")
    if not any_live:
        print("no-live-heavy-run")
    return 0


def cmd_clear(ws: Path, target: str | None) -> int:
    d = ws / ".auditooor"
    n = 0
    if d.is_dir():
        for p in d.glob(".heavy_lock_*.json"):
            if target and _lock_path(ws, target).name != p.name:
                continue
            try:
                p.unlink()
                n += 1
            except OSError:
                pass
    print(f"cleared {n} lock(s)")
    return 0


def cmd_run(ws: Path, target: str, cmd: list, ttl: int, now: float) -> int:
    lp = _lock_path(ws, target)
    lp.parent.mkdir(parents=True, exist_ok=True)
    existing = _read_lock(lp)
    if existing and _is_live(existing, ttl, now):
        print(f"[audit-heavy-lock] REFUSED: a live heavy '{target}' run holds the lock "
              f"(pid={existing.get('pid')}, age={int(now - float(existing.get('ts', now)))}s). "
              f"Not stacking (memory safety). Try next tick.", file=sys.stderr)
        return 3
    # (re)claim: stale or absent
    lp.write_text(json.dumps({"pid": os.getpid(), "ts": now, "target": target, "ttl": ttl}))
    try:
        return subprocess.call(cmd)
    finally:
        # release only if still ours
        cur = _read_lock(lp)
        if isinstance(cur, dict) and int(cur.get("pid", -1)) == os.getpid():
            try:
                lp.unlink()
            except OSError:
                pass


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="mode", required=True)
    pr = sub.add_parser("run")
    pr.add_argument("workspace")
    pr.add_argument("target")
    pr.add_argument("--ttl", type=int, default=DEFAULT_TTL)
    pr.add_argument("cmd", nargs=argparse.REMAINDER)
    ps = sub.add_parser("status")
    ps.add_argument("workspace")
    pc = sub.add_parser("clear")
    pc.add_argument("workspace")
    pc.add_argument("target", nargs="?", default=None)
    args = ap.parse_args(argv)
    # time.time() is fine here (normal CLI tool, not a resumable workflow script)
    now = time.time()
    ws = Path(args.workspace).resolve()
    if args.mode == "status":
        return cmd_status(ws, now)
    if args.mode == "clear":
        return cmd_clear(ws, args.target)
    if args.mode == "run":
        cmd = args.cmd
        if cmd and cmd[0] == "--":
            cmd = cmd[1:]
        if not cmd:
            print("usage: audit-heavy-lock.py run <ws> <target> -- <cmd...>", file=sys.stderr)
            return 1
        return cmd_run(ws, args.target, cmd, args.ttl, now)
    return 1


if __name__ == "__main__":
    sys.exit(main())
