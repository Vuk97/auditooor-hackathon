#!/usr/bin/env python3
"""Dispatch ``make audit`` without replaying a fresh baseline recipe.

The Makefile baseline recipe is intentionally large and historically used an
inner-shell ``exit 0`` for freshness. Make starts the next recipe line after
that shell exits, so the apparent short-circuit still ran engage.py. This
dispatcher owns the target boundary: fresh means return, stale means invoke the
baseline target exactly once.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


CANONICAL_STRICT_ENV = "AUDITOOOR_CANONICAL_STRICT"
NO_FAIL_FAST_ENV = "AUDITOOOR_AUDIT_NO_FAIL_FAST"


def _canonical_strict() -> bool:
    return os.environ.get(CANONICAL_STRICT_ENV) == "1"


def _run(repo: Path, args: list[str]) -> int:
    return subprocess.run(["make", "--no-print-directory", *args], cwd=repo).returncode


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parent.parent
    ws = args.workspace.expanduser().resolve()

    if _canonical_strict():
        if os.environ.get(NO_FAIL_FAST_ENV) == "1":
            print(
                f"audit-dispatch: {NO_FAIL_FAST_ENV}=1 is incompatible with "
                f"{CANONICAL_STRICT_ENV}=1",
                file=sys.stderr,
            )
            return 2
        args.strict = True

    if args.strict:
        for target in (
            ["prior-disclosure-index", f"WS={ws}"],
            [
                "intake-baseline",
                str(ws),
                "--strict-operator-truth",
                "--out-json",
                str(ws / "INTAKE_BASELINE.json"),
                "--out-md",
                str(ws / "INTAKE_BASELINE.md"),
            ],
        ):
            if target[0] == "intake-baseline":
                rc = subprocess.run([sys.executable, "tools/intake-baseline.py", *target[1:]], cwd=repo).returncode
            else:
                rc = _run(repo, target)
            if rc:
                return rc

    marker = [
        sys.executable,
        "tools/audit-completion-marker.py",
        "check",
        "--workspace",
        str(ws),
    ]
    if args.force or args.dry_run:
        marker.append("--force")
    if not args.force and not args.dry_run:
        result = subprocess.run(marker, cwd=repo)
        if result.returncode == 0:
            return 0
        if result.returncode >= 2:
            return result.returncode

    baseline = ["_audit-baseline", f"WS={ws}", "FORCE=1"]
    if args.strict:
        baseline.append("STRICT=1")
    if args.dry_run:
        baseline.append("DRY_RUN=1")
    return _run(repo, baseline)


if __name__ == "__main__":
    raise SystemExit(main())
