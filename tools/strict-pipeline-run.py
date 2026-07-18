#!/usr/bin/env python3
"""Run the ordered full pipeline and reject soft-failure output."""

from __future__ import annotations

import argparse
import os
import re
import signal
import subprocess
import sys
from pathlib import Path

SOFT_FAILURE = re.compile(
    r"(?i)^\s*(?:\[[^\]]+\]\s*)?(?:"
    r"WARN(?:ING)?\b|SUCCESS_WARN\b|SKIP(?:PED|PING)?\b|"
    r".*\bsoft[- ]skip\b|.*\btimed out\b|"
    r".*\b(?:status|reason)\s*[=:]\s*timeout\b|"
    r".*\btimeout\b.*\b(?:fail|exceed|block)\w*\b"
    r")"
)
ALLOWED_NA = re.compile(
    r"(?i)(?:0\s+(?:warning|advisory|skipped?|timeouts?)|"
    r"(?:warning|advisory|skipped?|timeouts?)\s*[=:]\s*0|"
    r"language[- ]conditional|class[- ]n/a|honest[- ]n/a|"
    r"no (?:cargo\.toml|\.?go files|zk circuits|mpc ceremony)|"
    r"no (?:solidity|evm) source)"
)


def _is_soft_failure(line: str) -> bool:
    """Classify status output, never shell comments as pipeline failures."""
    if line.lstrip().startswith("#"):
        return False
    return bool(SOFT_FAILURE.search(line) and not ALLOWED_NA.search(line))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a command is required")

    args.log.parent.mkdir(parents=True, exist_ok=True)
    with args.log.open("w", encoding="utf-8") as log:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1, start_new_session=True)
        assert proc.stdout is not None
        first_soft = None
        for line in proc.stdout:
            try:
                sys.stdout.write(line)
                sys.stdout.flush()
            except BrokenPipeError:
                # The caller may intentionally truncate output (for example,
                # `make ... | head`). The child still must finish and be
                # evaluated against the captured transcript.
                pass
            log.write(line)
            if first_soft is None and _is_soft_failure(line):
                first_soft = line.strip()
                print(f"[strict-pipeline-run] HARD-BLOCK: {first_soft}", file=sys.stderr)
                os.killpg(proc.pid, signal.SIGTERM)
                break
    rc = proc.wait()
    if first_soft is not None:
        return 1
    if rc:
        return rc

    soft = []
    for number, line in enumerate(args.log.read_text(encoding="utf-8").splitlines(), 1):
        if _is_soft_failure(line):
            soft.append((number, line.strip()))
    if soft:
        print(f"[strict-pipeline-run] ERROR: {len(soft)} soft-failure signal(s) in successful child output; see {args.log}", file=sys.stderr)
        for number, line in soft[:20]:
            print(f"  {args.log}:{number}: {line}", file=sys.stderr)
        if len(soft) > 20:
            print(f"  ... {len(soft) - 20} more", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
