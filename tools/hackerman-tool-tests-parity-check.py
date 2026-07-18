#!/usr/bin/env python3
"""Parity check: every tools/hackerman-*.py has a tools/tests/test_hackerman_*.py.

Walks tools/hackerman-*.py (including tools/hackerman-etl-from-*.py) and verifies
that each tool has a matching tools/tests/test_hackerman_<slug>.py file. The
match is computed by transforming each tool's filename into the canonical test
filename. Also flags orphan tests (test files with no matching tool).

Verdicts per tool:
- paired:        tool has matching test file
- missing-test:  tool exists but no matching test file
- orphan-test:   test file exists but no matching tool (emitted in summary)

Exit codes:
- 0  default (report only)
- 1  --strict and any tool has missing-test verdict

Wired by tools/hackerman-tool-tests-parity-check.py — branch
wave-1-hackerman-capability-lift (PR #726).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = REPO_ROOT / "tools"
TESTS_DIR = REPO_ROOT / "tools" / "tests"

TOOL_GLOBS: tuple[str, ...] = ("hackerman-*.py",)
TEST_PREFIX = "test_"


def tool_to_test_name(tool_filename: str) -> str:
    """Map 'hackerman-etl-from-foo.py' -> 'test_hackerman_etl_from_foo.py'.

    The Python test loader (`python -m unittest tools.tests.test_*`) requires
    underscore-only module names, so hyphens in tool filenames are normalized
    to underscores for the matching test filename.
    """
    stem = tool_filename[: -len(".py")] if tool_filename.endswith(".py") else tool_filename
    return f"{TEST_PREFIX}{stem.replace('-', '_')}.py"


def test_to_tool_name(test_filename: str) -> str:
    """Inverse of tool_to_test_name (best-effort).

    'test_hackerman_etl_from_foo.py' -> 'hackerman-etl-from-foo.py'.
    """
    stem = test_filename[: -len(".py")] if test_filename.endswith(".py") else test_filename
    if stem.startswith(TEST_PREFIX):
        stem = stem[len(TEST_PREFIX) :]
    return f"{stem.replace('_', '-')}.py"


def discover_tools(tools_dir: Path, globs: Iterable[str] = TOOL_GLOBS) -> list[Path]:
    seen: dict[str, Path] = {}
    for pattern in globs:
        for path in sorted(tools_dir.glob(pattern)):
            if not path.is_file():
                continue
            seen[path.name] = path
    return [seen[name] for name in sorted(seen)]


def discover_tests(tests_dir: Path) -> list[Path]:
    if not tests_dir.is_dir():
        return []
    return sorted(p for p in tests_dir.glob("test_hackerman_*.py") if p.is_file())


def _rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def build_report(tools_dir: Path, tests_dir: Path) -> dict:
    tools = discover_tools(tools_dir)
    tests = discover_tests(tests_dir)
    test_names = {t.name for t in tests}
    tool_names = {t.name for t in tools}

    rows: list[dict] = []
    paired = 0
    missing = 0
    for tool in tools:
        expected_test = tool_to_test_name(tool.name)
        if expected_test in test_names:
            verdict = "paired"
            paired += 1
        else:
            verdict = "missing-test"
            missing += 1
        rows.append(
            {
                "tool": tool.name,
                "tool_path": _rel(tool),
                "expected_test": expected_test,
                "verdict": verdict,
            }
        )

    # Compute orphan tests: tests whose expected source tool does not exist.
    orphan_rows: list[dict] = []
    for test in tests:
        candidate_tool = test_to_tool_name(test.name)
        if candidate_tool in tool_names:
            continue
        # Heuristic fallback: tool may use a hyphen that maps from an
        # underscore in the test name; try the original direction too.
        # E.g. test_hackerman_etl_miner_registry.py maps to
        # hackerman-etl-miner-registry.py which does not exist (real tool is
        # hackerman-etl-miner-registry-build.py). Flag honestly as orphan.
        orphan_rows.append(
            {
                "test": test.name,
                "test_path": _rel(test),
                "candidate_tool": candidate_tool,
                "verdict": "orphan-test",
            }
        )

    summary = {
        "tool_count": len(tools),
        "test_count": len(tests),
        "paired": paired,
        "missing_test": missing,
        "orphan_test": len(orphan_rows),
    }

    return {
        "tools_dir": _rel(tools_dir),
        "tests_dir": _rel(tests_dir),
        "summary": summary,
        "tools": rows,
        "orphan_tests": orphan_rows,
    }


def render_text(report: dict) -> str:
    s = report["summary"]
    lines: list[str] = []
    lines.append("hackerman-tool-tests-parity-check")
    lines.append(f"  tools_dir: {report['tools_dir']}")
    lines.append(f"  tests_dir: {report['tests_dir']}")
    lines.append(
        "  summary: tools={tool_count} paired={paired} missing-test={missing_test} "
        "orphan-test={orphan_test} test_count={test_count}".format(**s)
    )
    missing = [r for r in report["tools"] if r["verdict"] == "missing-test"]
    if missing:
        lines.append("")
        lines.append(f"missing-test ({len(missing)}):")
        for r in missing:
            lines.append(f"  - {r['tool']} -> expected {r['expected_test']}")
    if report["orphan_tests"]:
        lines.append("")
        lines.append(f"orphan-test ({len(report['orphan_tests'])}):")
        for r in report["orphan_tests"]:
            lines.append(f"  - {r['test']} (no matching tool {r['candidate_tool']})")
    if not missing and not report["orphan_tests"]:
        lines.append("")
        lines.append("all hackerman-* tools have matching tests; no orphan tests")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify every hackerman-* tool has a matching test_hackerman_* file.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="output format (default: text)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit 1 if any tool is missing a test",
    )
    parser.add_argument(
        "--tools-dir",
        default=str(TOOLS_DIR),
        help=f"tools directory to scan (default: {TOOLS_DIR})",
    )
    parser.add_argument(
        "--tests-dir",
        default=str(TESTS_DIR),
        help=f"tests directory to scan (default: {TESTS_DIR})",
    )
    args = parser.parse_args(argv)

    tools_dir = Path(args.tools_dir).resolve()
    tests_dir = Path(args.tests_dir).resolve()

    report = build_report(tools_dir, tests_dir)

    if args.format == "json":
        sys.stdout.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    else:
        sys.stdout.write(render_text(report))

    if args.strict and report["summary"]["missing_test"] > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
