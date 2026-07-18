#!/usr/bin/env python3
"""forever-loop-budget.py — bounded long-running-loop wrapper.

Background
----------
V5-P0-21 / Gap 38 / foot-gun #38: long-running shell loops
(``forever_overnight.sh``, ``loop_self_reflection.sh``,
``loop_dispatch_ready.sh``, ``loop_next_roadmap.sh``) ran for hours during
the 2026-04-26 session and produced 0 ROI. The pattern: kicked off
without a budget, no graceful exit path, no manifest of what was tried,
no resume info. Token waste accumulates fast.

This tool provides:

  1. ``ForeverLoopBudget`` — a context manager / decorator that any
     Python long-running loop can wrap itself in. Provides
     ``should_continue()``, signal handling for graceful SIGTERM, and a
     final manifest write.
  2. ``--cli-wrap`` — invocation form: run a child process with budget
     limits, kill it on exhaust, write a final manifest.

Discipline (Codex's spec)
-------------------------
Every long-running loop MUST have:
  - a budget guard (max_calls and/or max_minutes)
  - a graceful exit path (SIGTERM handler, ``should_continue()`` flag)
  - a final manifest with iters completed, exit reason, final state,
    resume info

This tool codifies all three.

Manifest schema
---------------
``schema=auditooor.forever_loop_budget.v1`` JSON document::

    {
      "schema": "auditooor.forever_loop_budget.v1",
      "name": "next-roadmap",
      "started_at_utc": "2026-04-26T12:00:00Z",
      "ended_at_utc": "2026-04-26T13:00:00Z",
      "elapsed_seconds": 3600,
      "iters_completed": 100,
      "max_calls": 100,
      "max_minutes": 60,
      "exit_reason": "max_calls_reached"
                    | "max_minutes_reached"
                    | "external_termination"
                    | "user_break"
                    | "natural_exit",
      "final_state": {...},
      "resume_info": {...}
    }

Discipline
----------
- Stdlib only.
- Manifest written even on SIGTERM (signal handler flushes).
- Atomic file writes (tmp + rename).
- Manifest path: ``<state-dir>/<name>_manifest_<ts>.json``.
  Default ``<state-dir>``: ``$AUDITOOOR_STATE/forever_loops`` or
  ``./.audit_logs/forever_loops``.

Library usage
-------------
::

    from forever_loop_budget import ForeverLoopBudget
    with ForeverLoopBudget(name="next-roadmap",
                           max_calls=100,
                           max_minutes=60) as loop:
        while loop.should_continue():
            do_one_iter()
            loop.tick(state={"current_pr": 42})

CLI wrap form
-------------
::

    python3 tools/forever-loop-budget.py --cli-wrap \\
        --name next-roadmap --max-minutes 60 -- bash loop.sh

Exits 0 when the wrapped command exits 0, 1 on the wrapped command's
non-zero exit, 124 when budget is exhausted (matches GNU timeout
convention).
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as _dt
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


# ---- exit reasons ---------------------------------------------------------

EXIT_NATURAL = "natural_exit"
EXIT_MAX_CALLS = "max_calls_reached"
EXIT_MAX_MINUTES = "max_minutes_reached"
EXIT_EXTERNAL = "external_termination"
EXIT_USER_BREAK = "user_break"


# ---- ForeverLoopBudget context manager ------------------------------------


class ForeverLoopBudget:
    """Bounded budget guard for long-running loops.

    Use as a context manager::

        with ForeverLoopBudget(name="next-roadmap",
                               max_calls=100,
                               max_minutes=60) as loop:
            while loop.should_continue():
                do_one_iter()
                loop.tick(state={"current_pr": 42})

    On context exit (natural, exception, or SIGTERM/SIGINT) a manifest
    JSON is written to ``state_dir/<name>_manifest_<ts>.json``.

    Args
    ----
    name: required label, also used in the manifest filename.
    max_calls: cap on ``tick()`` invocations. ``None`` = unlimited.
    max_minutes: wall-clock cap. ``None`` = unlimited.
    state_dir: where to write the manifest. Default: env
      ``AUDITOOOR_STATE/forever_loops`` or ``./.audit_logs/forever_loops``.
    install_signal_handlers: whether to wire SIGTERM/SIGINT to graceful
      exit (default True). Set False in tests so the test-runner's
      handlers are not clobbered.
    """

    def __init__(
        self,
        name: str,
        *,
        max_calls: int | None = None,
        max_minutes: float | None = None,
        state_dir: Path | None = None,
        install_signal_handlers: bool = True,
    ) -> None:
        if not name:
            raise ValueError("name must be a non-empty string")
        self.name = name
        self.max_calls = max_calls
        self.max_minutes = max_minutes
        self.state_dir = state_dir or self._default_state_dir()
        self.install_signal_handlers = install_signal_handlers
        self.iters_completed = 0
        self.exit_reason: str = EXIT_NATURAL
        self.final_state: dict[str, Any] = {}
        self.resume_info: dict[str, Any] = {}
        self._started_at: float = 0.0
        self._started_at_iso: str = ""
        self._terminated = False
        self._prev_handlers: dict[int, Any] = {}
        self._manifest_written = False
        self._manifest_path: Path | None = None

    @staticmethod
    def _default_state_dir() -> Path:
        env = os.environ.get("AUDITOOOR_STATE", "").strip()
        if env:
            return Path(env) / "forever_loops"
        return Path.cwd() / ".audit_logs" / "forever_loops"

    # ---- context manager protocol -----------------------------------------

    def __enter__(self) -> "ForeverLoopBudget":
        self._started_at = time.monotonic()
        self._started_at_iso = _utc_iso()
        if self.install_signal_handlers:
            for sig in (signal.SIGTERM, signal.SIGINT):
                try:
                    self._prev_handlers[sig] = signal.signal(
                        sig, self._on_signal
                    )
                except (ValueError, OSError):
                    # Some environments (e.g. non-main thread) cannot install
                    # signal handlers; that's fine — caller must drive
                    # ``should_continue()`` honestly.
                    pass
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        # Restore signal handlers (best effort).
        for sig, prev in self._prev_handlers.items():
            try:
                signal.signal(sig, prev)
            except (ValueError, OSError):
                pass
        # If an exception occurred, mark as user-break (not natural).
        if exc_type is not None and self.exit_reason == EXIT_NATURAL:
            self.exit_reason = EXIT_USER_BREAK
        if not self._manifest_written:
            try:
                self.write_manifest()
            except OSError:
                # Don't suppress the original exception with a manifest IO
                # error; just emit a stderr note.
                print(
                    f"[forever-loop-budget] could not write manifest for "
                    f"{self.name}: {exc}",
                    file=sys.stderr,
                )
        # Do not suppress exceptions.
        return False

    # ---- API ---------------------------------------------------------------

    def should_continue(self) -> bool:
        """Return False once any budget has been hit, or on SIGTERM."""
        if self._terminated:
            return False
        if self.max_calls is not None and self.iters_completed >= self.max_calls:
            self.exit_reason = EXIT_MAX_CALLS
            return False
        if self.max_minutes is not None:
            elapsed_min = (time.monotonic() - self._started_at) / 60.0
            if elapsed_min >= self.max_minutes:
                self.exit_reason = EXIT_MAX_MINUTES
                return False
        return True

    def tick(self, *, state: dict | None = None,
             resume: dict | None = None) -> None:
        """Increment iter counter and optionally update state/resume info."""
        self.iters_completed += 1
        if state is not None:
            self.final_state = dict(state)
        if resume is not None:
            self.resume_info = dict(resume)

    # ---- internals ---------------------------------------------------------

    def _on_signal(self, signum, frame) -> None:  # noqa: ARG002
        self._terminated = True
        self.exit_reason = EXIT_EXTERNAL
        # We do NOT raise here — the loop's own should_continue() check
        # will see the termination and exit gracefully on the next
        # iteration. Manifest is written at __exit__.

    def write_manifest(self) -> Path:
        """Write the manifest JSON. Atomic via tmp + rename."""
        self.state_dir.mkdir(parents=True, exist_ok=True)
        ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = self.state_dir / f"{self.name}_manifest_{ts}.json"
        elapsed_seconds = max(0.0, time.monotonic() - self._started_at)
        payload = {
            "schema": "auditooor.forever_loop_budget.v1",
            "name": self.name,
            "started_at_utc": self._started_at_iso,
            "ended_at_utc": _utc_iso(),
            "elapsed_seconds": round(elapsed_seconds, 3),
            "iters_completed": self.iters_completed,
            "max_calls": self.max_calls,
            "max_minutes": self.max_minutes,
            "exit_reason": self.exit_reason,
            "final_state": self.final_state,
            "resume_info": self.resume_info,
        }
        # Atomic tmp + rename.
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{self.name}_manifest_", suffix=".tmp",
            dir=str(self.state_dir),
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2)
                fh.write("\n")
            os.replace(tmp_name, path)
        except OSError:
            # Best-effort cleanup of the tmp file.
            with contextlib.suppress(OSError):
                os.remove(tmp_name)
            raise
        self._manifest_written = True
        self._manifest_path = path
        return path


def _utc_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---- CLI wrap mode --------------------------------------------------------


def _cli_wrap(args: argparse.Namespace) -> int:
    """Run a child command under a budget. Mirrors ``timeout(1)`` exit
    convention: 124 on budget exhaust, otherwise the child's exit code.
    """
    if not args.command:
        print("[forever-loop-budget] error: --cli-wrap requires a command",
              file=sys.stderr)
        return 2
    state_dir = args.state_dir or ForeverLoopBudget._default_state_dir()
    with ForeverLoopBudget(
        name=args.name,
        max_calls=None,  # CLI mode is wall-clock-bounded
        max_minutes=args.max_minutes,
        state_dir=state_dir,
        install_signal_handlers=False,
    ) as loop:
        try:
            proc = subprocess.Popen(args.command)
        except OSError as exc:
            print(f"[forever-loop-budget] could not exec child: {exc}",
                  file=sys.stderr)
            loop.exit_reason = EXIT_USER_BREAK
            return 2
        deadline = None
        if args.max_minutes is not None:
            deadline = time.monotonic() + args.max_minutes * 60
        try:
            while True:
                rc = proc.poll()
                if rc is not None:
                    loop.tick(state={"child_rc": rc})
                    return rc
                if deadline is not None and time.monotonic() >= deadline:
                    proc.terminate()
                    try:
                        proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)
                    loop.exit_reason = EXIT_MAX_MINUTES
                    loop.tick(state={"child_rc": "killed_on_budget"})
                    return 124
                time.sleep(1.0)
        except KeyboardInterrupt:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            loop.exit_reason = EXIT_USER_BREAK
            return 130


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=(
            "Forever-loop budget guard — wrap a long-running loop in a "
            "bounded context with a graceful exit and final manifest "
            "(V5-P0-21, foot-gun #38)."
        ),
    )
    p.add_argument("--name", required=True,
                   help="Loop name (manifest filename uses this).")
    p.add_argument("--max-calls", type=int, default=None,
                   help="Max tick() invocations (library mode only).")
    p.add_argument("--max-minutes", type=float, default=None,
                   help="Wall-clock budget in minutes.")
    p.add_argument("--state-dir", type=Path, default=None,
                   help="Manifest output dir (default: "
                        "$AUDITOOOR_STATE/forever_loops or "
                        "./.audit_logs/forever_loops).")
    p.add_argument("--cli-wrap", action="store_true",
                   help="Wrap an external command. Pass the command "
                        "after `--`.")
    p.add_argument("command", nargs=argparse.REMAINDER,
                   help="The command to run when --cli-wrap is set.")
    args = p.parse_args(argv)

    if args.cli_wrap:
        # Strip a leading `--` if present in the REMAINDER.
        cmd = args.command
        if cmd and cmd[0] == "--":
            cmd = cmd[1:]
        args.command = cmd
        return _cli_wrap(args)

    # No --cli-wrap: emit a doctrine reminder. The library API is the
    # primary entry point; running this script standalone without
    # --cli-wrap is almost always a misuse.
    print(
        "forever-loop-budget: import as a library "
        "(`from forever_loop_budget import ForeverLoopBudget`) "
        "or pass --cli-wrap with a command after `--`. "
        "See docs/FOREVER_LOOPS_DOCTRINE.md.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
