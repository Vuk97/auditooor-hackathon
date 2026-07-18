#!/usr/bin/env python3
"""Machine-readable batch-boundary preflight for memory and PR hygiene."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.batch_boundary_preflight.v1"
PASS = "PASS"
FAIL = "FAIL"
ERROR = "ERROR"
SKIPPED = "SKIPPED"


@dataclass(frozen=True)
class CheckSpec:
    key: str
    label: str
    command: tuple[str, ...]
    mandatory: bool


MANDATORY_CHECKS = (
    CheckSpec(
        key="memory_mcp_self_test",
        label="Memory MCP self-test",
        command=("python3", "tools/vault-mcp-server.py", "--self-test"),
        mandatory=True,
    ),
    CheckSpec(
        key="memory_context_parity",
        label="Memory context parity",
        command=("python3", "tools/memory-context-parity-check.py", "--strict"),
        mandatory=True,
    ),
)


def utc_now() -> str:
    return datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat()


def default_repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _trim(text: str | None, limit: int = 4000) -> str:
    if not text:
        return ""
    if len(text) <= limit:
        return text
    return text[-limit:]


def run_check(spec: CheckSpec, repo_root: Path, timeout: float) -> dict[str, Any]:
    command = list(spec.command)
    try:
        proc = subprocess.run(command, cwd=repo_root, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        return {
            "key": spec.key,
            "label": spec.label,
            "mandatory": spec.mandatory,
            "status": ERROR,
            "exit_code": None,
            "command": command,
            "stdout": _trim(exc.stdout if isinstance(exc.stdout, str) else ""),
            "stderr": _trim(exc.stderr if isinstance(exc.stderr, str) else ""),
            "error": f"timed out after {timeout:g}s",
        }
    except OSError as exc:
        return {
            "key": spec.key,
            "label": spec.label,
            "mandatory": spec.mandatory,
            "status": ERROR,
            "exit_code": None,
            "command": command,
            "stdout": "",
            "stderr": "",
            "error": str(exc),
        }

    return {
        "key": spec.key,
        "label": spec.label,
        "mandatory": spec.mandatory,
        "status": PASS if proc.returncode == 0 else FAIL,
        "exit_code": proc.returncode,
        "command": command,
        "stdout": _trim(proc.stdout),
        "stderr": _trim(proc.stderr),
    }


def skipped_pr_hygiene(*, mandatory: bool = False) -> dict[str, Any]:
    return {
        "key": "pr_hygiene",
        "label": "PR hygiene",
        "mandatory": mandatory,
        "status": FAIL if mandatory else SKIPPED,
        "exit_code": None,
        "command": ["python3", "tools/pr-hygiene-check.py", "<pr-body-path>"],
        "stdout": "",
        "stderr": "",
        "reason": "PR body path required by --pr-strict" if mandatory else "no PR body path supplied",
    }


def build_report(
    repo_root: Path,
    *,
    pr_body: Path | None,
    strict: bool,
    pr_strict: bool,
    timeout: float,
) -> dict[str, Any]:
    repo_root = repo_root.expanduser().resolve()
    checks = [run_check(spec, repo_root, timeout) for spec in MANDATORY_CHECKS]

    if pr_body is None:
        checks.append(skipped_pr_hygiene(mandatory=pr_strict))
    else:
        command = ["python3", "tools/pr-hygiene-check.py", str(pr_body)]
        if pr_strict:
            command.append("--strict")
        checks.append(
            run_check(
                CheckSpec(
                    key="pr_hygiene",
                    label="PR hygiene",
                    command=tuple(command),
                    mandatory=pr_strict,
                ),
                repo_root,
                timeout,
            )
        )

    mandatory_failures = [check["key"] for check in checks if check["mandatory"] and check["status"] != PASS]
    optional_failures = [check["key"] for check in checks if not check["mandatory"] and check["status"] in {FAIL, ERROR}]
    skipped_optional = [check["key"] for check in checks if not check["mandatory"] and check["status"] == SKIPPED]

    if mandatory_failures:
        overall_status = "BLOCKED"
    elif optional_failures:
        overall_status = "WARN"
    elif skipped_optional:
        overall_status = "ADVISORY"
    else:
        overall_status = "READY"

    return {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "repo_root": str(repo_root),
        "mode": "strict" if strict else "advisory",
        "strict": strict,
        "pr_strict": pr_strict,
        "overall_status": overall_status,
        "exit_would_fail": bool((strict and mandatory_failures) or (pr_strict and "pr_hygiene" in mandatory_failures)),
        "mandatory_failures": mandatory_failures,
        "optional_failures": optional_failures,
        "skipped_optional": skipped_optional,
        "checks": checks,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Emit JSON batch-boundary preflight status.")
    parser.add_argument("--repo-root", type=Path, default=default_repo_root(), help="Repository root to run checks from.")
    parser.add_argument("--pr-body", type=Path, help="Optional PR body markdown path to include PR hygiene.")
    parser.add_argument("--strict", action="store_true", help="Exit nonzero when mandatory memory checks fail.")
    parser.add_argument("--pr-strict", action="store_true", help="Require --pr-body and run PR hygiene in fail-closed mode.")
    parser.add_argument("--timeout", type=float, default=120.0, help="Per-check subprocess timeout in seconds.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    report = build_report(
        args.repo_root,
        pr_body=args.pr_body,
        strict=args.strict,
        pr_strict=args.pr_strict,
        timeout=args.timeout,
    )
    print(json.dumps(report, sort_keys=True))
    return 1 if report["exit_would_fail"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
