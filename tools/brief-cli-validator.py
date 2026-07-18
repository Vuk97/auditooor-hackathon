#!/usr/bin/env python3
# r36-rebuttal: lane-LIFT-20-ENFORCEMENT-FRAGILITY-AUDIT registered via tools/agent-pathspec-register.py
"""brief-cli-validator.py

Brief-vs-CLI drift detector. Walks a lane brief markdown file, extracts
every `python3 tools/X.py ... --flag ...` (and `bash tools/X.sh ... --flag`)
invocation, then verifies via `--help` that --flag actually exists.

Catches stale briefs before agent dispatch. Empirical anchor: LIFT-14
brief (2026-05-26) cited dispatcher flags that did not exist in the
current CLI, wasting agent cycles on non-existent flag invocations.

Schema: auditooor.brief_cli_validator.v1
Exit codes:
  0 - all flags exist (PASS)
  1 - at least one flag is stale (FAIL)
  2 - internal error (e.g. brief file unreadable)

Usage:
  python3 tools/brief-cli-validator.py <brief.md> [--json] [--strict]

  --strict: also fail if any cited tool/script is missing on disk.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

SCHEMA = "auditooor.brief_cli_validator.v1"

# Matches: python3 tools/X.py ... --flag1 ... --flag2 value
# Also handles: bash tools/X.sh, ./tools/X.py
_INVOCATION_RE = re.compile(
    r"""
    (?:python3?|bash|sh)?\s*
    \.?/?
    (tools/[A-Za-z0-9_./-]+\.(?:py|sh))
    ((?:\s+(?:--?[A-Za-z][A-Za-z0-9_-]*|\S+))*)
    """,
    re.VERBOSE,
)

_FLAG_RE = re.compile(r"(?<![A-Za-z0-9])(--?[A-Za-z][A-Za-z0-9_-]*)\b")


def extract_invocations(brief_text: str) -> list[tuple[str, list[str], int]]:
    """Return list of (tool_path, flag_list, line_number) tuples."""
    out: list[tuple[str, list[str], int]] = []
    in_code = False
    for line_no, raw_line in enumerate(brief_text.splitlines(), start=1):
        if raw_line.strip().startswith("```"):
            in_code = not in_code
            continue
        stripped = raw_line.lstrip()
        if stripped.startswith("- ") or stripped.startswith("* "):
            if not re.search(r"\btools/[A-Za-z0-9_./-]+\.(py|sh)\b", raw_line):
                continue
        for m in _INVOCATION_RE.finditer(raw_line):
            tool_path = m.group(1)
            arg_tail = m.group(2) or ""
            flags = _FLAG_RE.findall(arg_tail)
            if not flags and not in_code:
                continue
            out.append((tool_path, flags, line_no))
    return out


def get_tool_help(repo_root: Path, tool_path: str, timeout: int = 10) -> tuple[bool, str]:
    """Return (success, help_text)."""
    full_path = repo_root / tool_path
    if not full_path.exists():
        return (False, f"<file-not-found: {tool_path}>")
    interpreter = ["python3"] if tool_path.endswith(".py") else ["bash"]
    try:
        proc = subprocess.run(
            interpreter + [str(full_path), "--help"],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(repo_root),
        )
        help_text = (proc.stdout or "") + "\n" + (proc.stderr or "")
        return (proc.returncode == 0 or bool(help_text.strip()), help_text)
    except subprocess.TimeoutExpired:
        return (False, "<help-timed-out>")
    except (OSError, subprocess.SubprocessError) as exc:
        return (False, f"<help-error: {exc}>")


def validate_flag(flag: str, help_text: str) -> bool:
    """Check whether the flag appears in help text."""
    bare = flag.split("=", 1)[0]
    pattern = re.compile(rf"(?<![A-Za-z0-9]){re.escape(bare)}\b")
    return bool(pattern.search(help_text))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("brief", help="Path to lane brief markdown")
    ap.add_argument("--json", action="store_true", help="Emit JSON report")
    ap.add_argument("--strict", action="store_true",
                    help="Fail if any cited tool is missing on disk")
    ap.add_argument("--workspace", default=None,
                    help="Workspace root (default: cwd or auditooor-mcp)")
    args = ap.parse_args()

    brief_path = Path(args.brief)
    if not brief_path.is_file():
        print(f"ERROR: brief not found: {brief_path}", file=sys.stderr)
        return 2

    repo_root = Path(args.workspace) if args.workspace else Path("/Users/wolf/auditooor-mcp")
    if not repo_root.is_dir():
        repo_root = Path.cwd()

    text = brief_path.read_text(errors="replace")
    invocations = extract_invocations(text)

    findings: list[dict] = []
    help_cache: dict[str, tuple[bool, str]] = {}

    for tool_path, flags, line_no in invocations:
        if tool_path not in help_cache:
            help_cache[tool_path] = get_tool_help(repo_root, tool_path)
        tool_ok, help_text = help_cache[tool_path]
        if not tool_ok:
            findings.append({
                "verdict": "fail-tool-missing-or-help-broken",
                "tool_path": tool_path,
                "line": line_no,
                "detail": help_text[:200],
            })
            continue
        for flag in flags:
            if flag in ("-h", "--help", "-c", "-e", "-i"):
                continue
            if not validate_flag(flag, help_text):
                findings.append({
                    "verdict": "fail-stale-flag",
                    "tool_path": tool_path,
                    "flag": flag,
                    "line": line_no,
                })

    pass_count = len(invocations) - len([f for f in findings if f["verdict"].startswith("fail")])
    report = {
        "schema": SCHEMA,
        "brief": str(brief_path),
        "invocations_total": len(invocations),
        "passing": pass_count,
        "findings": findings,
        "verdict": "pass" if not findings else "fail",
    }

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"brief-cli-validator: {brief_path}")
        print(f"  invocations: {len(invocations)}")
        print(f"  passing: {pass_count}")
        print(f"  findings: {len(findings)}")
        for f in findings:
            print(f"  - {f.get('verdict')} | {f.get('tool_path')} | "
                  f"flag={f.get('flag','-')} | line={f.get('line','-')}")
        print(f"VERDICT: {report['verdict']}")

    if findings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
