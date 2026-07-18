#!/usr/bin/env python3
"""audit-progress.py — PR 208 operator-facing progress surface.

Wraps `tools/engage.py --stage all` (or a dry-run) and streams structured
stage start/end lines. This is *operator visibility only*: the underlying
engagement artifacts (drafts in `submissions/staging/`, engage_report.md,
etc.) are the load-bearing outputs. Progress lines are not proof.

Status vocabulary mirrors engage.py exactly: {started, ok, failed, skipped}.
No new verbs are introduced.

Emitted line format:

    [stage=orient started]
    [stage=orient ok 32.1s]
    [stage=scan failed 4.8s]
    [stage=cross-ws-patterns skipped 0.1s]

On stage failure, prints the last 15 lines of the stage's stdout/stderr tail
and exits 1. On overall success, exits 0 and prints a one-line tally.

`--dry-run` plumbs through to engage.py --dry-run (no execution, just the
planned stage list); used by `make audit DRY_RUN=1`.

Stdlib only. No network. Does not invoke any binary not already on PATH
within the repo's existing tooling envelope.
"""
from __future__ import annotations

import argparse
import csv
import os
import re
import subprocess
import sys
import time
from collections import deque
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
ENGAGE = HERE / "engage.py"


def _ensure_git_work_tree(repo: Path) -> int | None:
    """Foot-gun #13a guard — refuse to run if ``repo`` is not a real git
    work tree.

    Parallel-agent dispatch sometimes copies or symlinks ``audit-progress.py``
    into a harness temp dir whose parent is *not* a git checkout. When that
    happens engage.py's downstream calls silently target whatever git repo
    happens to be CWD — or none at all — and the operator has no way to
    notice. Verifying ``git rev-parse --is-inside-work-tree`` against
    ``REPO`` makes the failure loud.

    Returns ``None`` on success and an exit code (1) on failure. Any
    unexpected error from the ``git`` invocation (missing binary, etc.)
    also fails closed.
    """
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=10,
        )
    except FileNotFoundError:
        print(
            "audit-progress: working tree not a git repo (GIT_WORK_TREE unset?)"
            " — git binary not found",
            file=sys.stderr,
        )
        return 1
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(
            "audit-progress: working tree not a git repo (GIT_WORK_TREE unset?)"
            f" — git probe failed: {exc}",
            file=sys.stderr,
        )
        return 1
    if proc.returncode != 0 or proc.stdout.strip() != "true":
        print(
            "audit-progress: working tree not a git repo (GIT_WORK_TREE unset?)",
            file=sys.stderr,
        )
        return 1
    return None

# engage.py emits `[stage: NAME] ...` for header lines. We detect the first
# such line per stage to emit our `started` marker, and we detect the final
# `[stage: NAME] STATUS ...` line recorded by engage.py's summary path.
#
# The canonical status tokens engage.py uses are:
#   SUCCESS, SUCCESS_WARN ..., SKIPPED ..., FAIL ...
# We normalize them into {ok, skipped, failed} for the progress surface.
STAGE_LINE_RE = re.compile(r"^\[stage:\s*(?P<name>[a-z][a-z0-9\-]*)\]\s*(?P<rest>.*)$")

# engage.py's summary printer emits a table; we do not re-parse it. We derive
# per-stage status by watching the stdout stream and the final exit code.
STATUS_MAP = {
    "SUCCESS": "ok",
    "SUCCESS_WARN": "ok",  # warn still means the stage produced artifacts
    "SKIPPED": "skipped",
    "FAIL": "failed",
}


def _normalize_status(raw: str) -> str:
    for prefix, norm in STATUS_MAP.items():
        if raw.startswith(prefix):
            return norm
    return "ok"  # conservative default; engage.py's exit code is the truth


def _build_engage_cmd(workspace: Path, dry_run: bool, extra: list[str]) -> list[str]:
    cmd = [sys.executable, str(ENGAGE), "--workspace", str(workspace)]
    if dry_run:
        cmd.append("--dry-run")
    else:
        cmd += ["--stage", "all"]
        # I8 — when an opt-in campaign is enabled, run the chain to
        # completion so the campaign (last in chain) is always reached.
        # Without this, `quality-score` (which fails on a fresh workspace
        # with no submissions yet) trips `--fail-fast` and skips
        # `campaign-source-mine` silently. Operator override:
        # AUDITOOOR_AUDIT_NO_FAIL_FAST=1.
        canonical_strict = os.environ.get("AUDITOOOR_CANONICAL_STRICT") == "1"
        opt_in_campaigns = (
            os.environ.get("CAMPAIGN_SOURCE_MINE") == "1"
            or os.environ.get("AUDITOOOR_AUDIT_NO_FAIL_FAST") == "1"
        )
        if canonical_strict or not opt_in_campaigns:
            cmd.append("--fail-fast")
    cmd += extra
    return cmd


def _stream_and_classify(
    proc: subprocess.Popen,
    out_stream,
) -> tuple[dict[str, dict], deque]:
    """Read engage.py stdout line-by-line, emit progress markers, capture tail."""
    stages: dict[str, dict] = {}  # name -> {started_at, ended, status, tail}
    current: str | None = None
    recent_tail: deque = deque(maxlen=15)  # last 15 lines globally (for failure)

    assert proc.stdout is not None
    for raw_line in proc.stdout:
        line = raw_line.rstrip("\n")
        recent_tail.append(line)
        # Mirror engage.py output verbatim so the operator sees the real logs.
        print(line, file=out_stream, flush=True)

        m = STAGE_LINE_RE.match(line)
        if not m:
            if current is not None:
                stages[current]["tail"].append(line)
            continue

        name = m.group("name")
        rest = m.group("rest").strip()

        # First sighting of a stage → emit `started` marker.
        if name not in stages:
            stages[name] = {
                "started_at": time.time(),
                "ended_at": None,
                "ended": False,
                "status": None,
                "warning": False,
                "tail": deque(maxlen=15),
            }
            print(f"[stage={name} started]", file=out_stream, flush=True)
            current = name

        # engage.py prints a terminal status line per stage via the _run
        # wrapper, e.g. `[stage: track-submissions] SUCCESS updated`.
        # We match on the first word after the bracket being a known token.
        first_tok = rest.split(" ", 1)[0] if rest else ""
        if first_tok in STATUS_MAP and not stages[name]["ended"]:
            now = time.time()
            dur = now - stages[name]["started_at"]
            norm = _normalize_status(rest)
            stages[name]["ended"] = True
            stages[name]["ended_at"] = now
            stages[name]["status"] = norm
            stages[name]["warning"] = first_tok == "SUCCESS_WARN"
            print(f"[stage={name} {norm} {dur:.1f}s]", file=out_stream, flush=True)

        stages[name]["tail"].append(line)

    return stages, recent_tail


def _finalize_unterminated(stages: dict[str, dict], overall_rc: int, out_stream) -> None:
    """Any stage we saw `started` on but not a terminal status line."""
    for name, meta in stages.items():
        if meta["ended"]:
            continue
        now = time.time()
        dur = now - meta["started_at"]
        meta["ended_at"] = now
        if overall_rc == 0:
            meta["status"] = "ok"
            print(f"[stage={name} ok {dur:.1f}s]", file=out_stream, flush=True)
        else:
            meta["status"] = "failed"
            print(f"[stage={name} failed {dur:.1f}s]", file=out_stream, flush=True)


def render_csv(stages: dict[str, dict], out_stream) -> None:
    """Write per-stage rows as CSV: stage,status,elapsed_secs,started_at_epoch.

    Order preserves the dict insertion order, which mirrors the order in which
    engage.py first emitted each `[stage: NAME] ...` header. `started_at_epoch`
    is the wall-clock float when audit-progress.py first saw the stage; useful
    for diffing two runs or feeding into a spreadsheet.
    """
    writer = csv.writer(out_stream)
    writer.writerow(["stage", "status", "elapsed_secs", "started_at_epoch"])
    for name, meta in stages.items():
        # finalize() guarantees a status; default to "" if a caller passes a
        # half-finalized dict (e.g. unit tests).
        status = meta.get("status") or ""
        started_at = meta.get("started_at") or 0.0
        ended_at = meta.get("ended_at")
        if ended_at is not None:
            elapsed = ended_at - started_at
        else:
            elapsed = (time.time() - started_at) if started_at else 0.0
        writer.writerow([name, status, f"{elapsed:.1f}", f"{started_at:.3f}"])


def run_audit(
    workspace: Path,
    dry_run: bool,
    extra: list[str],
    csv_path: Path | None = None,
) -> int:
    cmd = _build_engage_cmd(workspace, dry_run, extra)
    print(f"[audit-progress] cmd: {' '.join(cmd)}", flush=True)
    t0 = time.time()

    proc = subprocess.Popen(
        cmd,
        cwd=str(REPO),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    try:
        stages, recent_tail = _stream_and_classify(proc, sys.stdout)
        rc = proc.wait()
    except KeyboardInterrupt:
        proc.kill()
        print("[audit-progress] aborted by operator", flush=True)
        return 130

    _finalize_unterminated(stages, rc, sys.stdout)

    total = time.time() - t0
    n_ok = sum(1 for m in stages.values() if m.get("status") == "ok")
    n_warn = sum(1 for m in stages.values() if m.get("warning"))
    n_fail = sum(1 for m in stages.values() if m.get("status") == "failed")
    n_skip = sum(1 for m in stages.values() if m.get("status") == "skipped")

    if csv_path is not None:
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        with csv_path.open("w", newline="") as f:
            render_csv(stages, f)
        print(f"[audit-progress] wrote CSV: {csv_path}", flush=True)

    if rc != 0:
        print("", flush=True)
        print("[audit-progress] FAILED — error tail (last 15 lines):", flush=True)
        for line in recent_tail:
            print(f"  {line}", flush=True)
        print(
            f"[audit-progress] stages ok={n_ok} warn={n_warn} failed={n_fail} "
            f"skipped={n_skip} elapsed={total:.1f}s",
            flush=True,
        )
        return 1

    print(
        f"[audit-progress] DONE stages ok={n_ok} warn={n_warn} failed={n_fail} "
        f"skipped={n_skip} elapsed={total:.1f}s",
        flush=True,
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "Lightweight operator progress surface for `make audit`. "
            "Streams engage.py stage markers as "
            "[stage=<name> {started,ok,failed,skipped} <dur>]."
        ),
    )
    ap.add_argument("--workspace", type=Path, required=True,
                    help="Audit workspace directory.")
    ap.add_argument("--dry-run", action="store_true",
                    help="Plan only: call engage.py --dry-run and exit 0.")
    ap.add_argument("--csv", type=Path, default=None, metavar="PATH",
                    help=("Write per-stage summary as CSV "
                          "(columns: stage,status,elapsed_secs,started_at_epoch). "
                          "Spreadsheet-friendly progress export."))
    ap.add_argument("engage_extra", nargs=argparse.REMAINDER,
                    help="Pass-through args to engage.py (after `--`).")
    args = ap.parse_args()

    # Foot-gun #13a guard — fail fast if ``REPO`` is not a real git work
    # tree (parallel-agent dispatch sometimes drops the script into a
    # harness temp dir).
    rc = _ensure_git_work_tree(REPO)
    if rc is not None:
        return rc

    ws = args.workspace.expanduser().resolve()
    if not ws.exists() or not ws.is_dir():
        print(f"[audit-progress] ERR workspace not found / not a dir: {ws}",
              file=sys.stderr)
        return 2

    extra = list(args.engage_extra or [])
    if extra and extra[0] == "--":
        extra = extra[1:]

    csv_path = args.csv.expanduser().resolve() if args.csv else None
    return run_audit(ws, args.dry_run, extra, csv_path=csv_path)


if __name__ == "__main__":
    sys.exit(main())
