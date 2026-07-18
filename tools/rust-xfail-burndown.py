#!/usr/bin/env python3
"""Summarize the Rust generated-XFAIL burndown state.

The full Rust fixture harness now includes the report-backed detector helper.
This tool records both surfaces together:

* `tools/rust-fixture-regression-list.py --summary`
* `detectors/rust_wave1/test_fixtures/test_detectors.sh`

Generated helper additions are allowed to produce residual `XFAIL` assertions.
Non-XFAIL harness failures remain hard failures.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.rust_xfail_burndown.v1"
DEFAULT_JSON_OUT = Path("reports/rust_xfail_burndown_2026-05-05.json")
DEFAULT_MD_OUT = Path("docs/RUST_XFAIL_BURNDOWN_2026-05-05.md")
HARNESS = Path("detectors/rust_wave1/test_fixtures/test_detectors.sh")


@dataclass(frozen=True)
class CommandResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class HelperSummary:
    detectors: int
    residual_skips: int


@dataclass(frozen=True)
class XfailRow:
    detector_id: str
    mode: str
    reason: str


@dataclass(frozen=True)
class HarnessSummary:
    passed: int
    total: int
    generated_residual_xfail: int
    failures: list[str]
    xfails: list[XfailRow]


def _run(command: list[str], *, cwd: Path, timeout: int) -> CommandResult:
    proc = subprocess.run(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
    )
    return CommandResult(command=command, returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)


def parse_helper_summary(text: str) -> HelperSummary:
    values: dict[str, int] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key in {"detectors", "residual_skips"}:
            try:
                values[key] = int(value)
            except ValueError as exc:
                raise ValueError(f"invalid helper summary value for {key}: {value!r}") from exc

    missing = sorted({"detectors", "residual_skips"} - values.keys())
    if missing:
        raise ValueError(f"helper summary missing keys: {', '.join(missing)}")
    return HelperSummary(detectors=values["detectors"], residual_skips=values["residual_skips"])


def parse_harness_summary(text: str) -> HarnessSummary:
    passed: int | None = None
    total: int | None = None
    generated_xfail = 0
    failures: list[str] = []
    xfails: list[XfailRow] = []
    section: str | None = None

    summary_re = re.compile(r"Rust wave1 regression:\s+(?P<passed>\d+)/(?P<total>\d+) passed")
    xfail_count_re = re.compile(r"Generated fixture residual xfail:\s+(?P<count>\d+)")
    detail_re = re.compile(r"-\s+(?P<detector>\S+)\s+(?P<mode>positive|negative):\s+(?P<reason>.+)")

    for raw_line in text.splitlines():
        line = raw_line.strip()
        summary_match = summary_re.search(line)
        if summary_match:
            passed = int(summary_match.group("passed"))
            total = int(summary_match.group("total"))
            continue

        xfail_count_match = xfail_count_re.search(line)
        if xfail_count_match:
            generated_xfail = int(xfail_count_match.group("count"))
            continue

        if line == "Failures:":
            section = "failures"
            continue
        if line == "Generated residual xfails:":
            section = "xfails"
            continue
        if not line:
            section = None
            continue

        if section == "failures" and line.startswith("- "):
            failures.append(line[2:])
            continue
        if section == "xfails" and line.startswith("- "):
            detail_match = detail_re.match(line)
            if detail_match:
                xfails.append(
                    XfailRow(
                        detector_id=detail_match.group("detector"),
                        mode=detail_match.group("mode"),
                        reason=detail_match.group("reason"),
                    )
                )
            else:
                xfails.append(XfailRow(detector_id="", mode="", reason=line[2:]))

    if passed is None or total is None:
        raise ValueError("harness summary missing Rust wave1 regression total")
    return HarnessSummary(
        passed=passed,
        total=total,
        generated_residual_xfail=generated_xfail,
        failures=failures,
        xfails=xfails,
    )


def _static_regression_ids(repo: Path) -> set[str]:
    harness = repo / HARNESS
    try:
        text = harness.read_text(encoding="utf-8")
    except OSError:
        return set()

    match = re.search(r"^DETECTORS=\(\n(?P<body>.*?)^\)", text, flags=re.M | re.S)
    if not match:
        return set()

    out: set[str] = set()
    for raw_line in match.group("body").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        out.add(line.split()[0])
    return out


def _load_residual_skip_rows(repo: Path, coverage_report: Path, helper_summary: HelperSummary) -> list[dict[str, Any]]:
    report_path = coverage_report if coverage_report.is_absolute() else repo / coverage_report
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    rows = payload.get("per_detector")
    if not isinstance(rows, list):
        return []

    static_ids = _static_regression_ids(repo)
    residual: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        detector_id = str(row.get("detector_id", ""))
        if detector_id in static_ids:
            continue
        if row.get("fixture_pair_present") is not True:
            residual.append(row)
        elif row.get("nested_detector") is True:
            residual.append(row)
        elif row.get("detector_group") not in (None, "rust_wave1"):
            residual.append(row)

    residual.sort(key=lambda row: str(row.get("detector_id", "")))
    if len(residual) != helper_summary.residual_skips:
        return []
    return residual


def _status(
    *,
    helper: HelperSummary,
    helper_result: CommandResult,
    harness: HarnessSummary,
    harness_result: CommandResult,
) -> tuple[str, list[str]]:
    notes: list[str] = []
    if helper_result.returncode != 0:
        notes.append(f"helper exited {helper_result.returncode}")
    if harness_result.returncode != 0:
        notes.append(f"harness exited {harness_result.returncode}")
    if harness.failures:
        notes.append(f"non-xfail harness failures: {len(harness.failures)}")
    expected_total = helper.detectors * 2
    if harness.total != expected_total:
        notes.append(f"harness total {harness.total} != helper detector pairs {expected_total}")
    if harness.passed + harness.generated_residual_xfail + len(harness.failures) != harness.total:
        notes.append("harness pass/xfail/fail counts do not sum to total")

    if notes:
        return "needs_attention", notes
    if harness.generated_residual_xfail:
        return "pass_with_generated_xfail", notes
    return "pass_no_generated_xfail", notes


def build_report(
    repo: Path,
    *,
    helper_result: CommandResult,
    harness_result: CommandResult,
    coverage_report: Path,
) -> dict[str, Any]:
    helper = parse_helper_summary(helper_result.stdout)
    harness = parse_harness_summary(harness_result.stdout)
    status, notes = _status(
        helper=helper,
        helper_result=helper_result,
        harness=harness,
        harness_result=harness_result,
    )
    residual_skip_rows = _load_residual_skip_rows(repo, coverage_report, helper)

    return {
        "schema": SCHEMA_VERSION,
        "repo_root": str(repo.resolve()),
        "status": status,
        "notes": notes,
        "helper": {
            **asdict(helper),
            "command": helper_result.command,
            "returncode": helper_result.returncode,
        },
        "harness": {
            "command": harness_result.command,
            "returncode": harness_result.returncode,
            "passed": harness.passed,
            "total": harness.total,
            "generated_residual_xfail": harness.generated_residual_xfail,
            "failures": harness.failures,
            "xfail_count_by_mode": {
                "positive": sum(1 for row in harness.xfails if row.mode == "positive"),
                "negative": sum(1 for row in harness.xfails if row.mode == "negative"),
            },
            "xfails": [asdict(row) for row in harness.xfails],
        },
        "consistency": {
            "harness_total_matches_helper_detector_pairs": harness.total == helper.detectors * 2,
            "helper_detector_assertions": helper.detectors * 2,
            "non_xfail_failures": len(harness.failures),
            "harness_exit_zero": harness_result.returncode == 0,
            "helper_exit_zero": helper_result.returncode == 0,
        },
        "burndown": {
            "current_green_assertions": harness.passed,
            "total_assertions": harness.total,
            "generated_residual_xfail": harness.generated_residual_xfail,
            "generated_residual_xfail_remaining": harness.generated_residual_xfail,
            "helper_residual_skip_detectors": helper.residual_skips,
            "next_goal": "reduce generated residual XFAIL to 0 without hiding fixture-backed detectors",
        },
        "residual_skip_detectors": [
            {
                "detector_id": row.get("detector_id", ""),
                "detector_path": row.get("detector_path", ""),
                "fixture_pair_present": row.get("fixture_pair_present"),
                "nested_detector": row.get("nested_detector"),
                "detector_group": row.get("detector_group"),
            }
            for row in residual_skip_rows
        ],
    }


def _render_markdown(payload: dict[str, Any]) -> str:
    helper = payload["helper"]
    harness = payload["harness"]
    consistency = payload["consistency"]
    burndown = payload["burndown"]
    lines = [
        "# Rust XFAIL Burndown - 2026-05-05",
        "",
        "Generated from the report-backed Rust regression helper plus the full Rust fixture harness.",
        "",
        "## Summary",
        "",
        f"- Status: `{payload['status']}`.",
        f"- Helper summary: **{helper['detectors']}** fixture-backed detectors, **{helper['residual_skips']}** residual skipped detector rows.",
        f"- Full harness: **{harness['passed']}/{harness['total']}** passed with **{harness['generated_residual_xfail']}** generated residual XFAIL assertions.",
        f"- Harness exit: `{harness['returncode']}`; non-XFAIL failures: **{consistency['non_xfail_failures']}**.",
        f"- Detector/assertion consistency: `{consistency['harness_total_matches_helper_detector_pairs']}` ({consistency['helper_detector_assertions']} helper-derived assertions).",
        "",
        "## Commands",
        "",
        f"- Helper: `{' '.join(helper['command'])}`",
        f"- Harness: `{' '.join(harness['command'])}`",
        "",
        "## Burndown",
        "",
        f"- Current green assertions: **{burndown['current_green_assertions']}**.",
        f"- Generated residual XFAIL remaining: **{burndown['generated_residual_xfail_remaining']}**.",
        f"- Residual skipped detector rows outside the helper/harness set: **{burndown['helper_residual_skip_detectors']}**.",
        f"- Next goal: {burndown['next_goal']}.",
    ]
    if payload["notes"]:
        lines.extend(["", "## Notes", ""])
        lines.extend(f"- {note}" for note in payload["notes"])
    if payload["residual_skip_detectors"]:
        lines.extend(
            [
                "",
                "## Residual Skipped Detectors",
                "",
                "| detector | path | reason |",
                "|---|---|---|",
            ]
        )
        for row in payload["residual_skip_detectors"]:
            reason = "missing fixture pair"
            if row["nested_detector"] is True:
                reason = "nested or non-top-level detector"
            lines.append(f"| `{row['detector_id']}` | `{row['detector_path']}` | {reason} |")
    return "\n".join(lines) + "\n"


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo_root", nargs="?", default=".", help="repo root")
    parser.add_argument("--json-out", type=Path, default=DEFAULT_JSON_OUT)
    parser.add_argument("--md-out", type=Path, default=DEFAULT_MD_OUT)
    parser.add_argument("--coverage-report", type=Path, default=Path("reports/rust_detector_coverage_2026-05-05.json"))
    parser.add_argument("--helper-output", type=Path, help="parse helper stdout from a file instead of running it")
    parser.add_argument("--harness-output", type=Path, help="parse harness stdout from a file instead of running it")
    parser.add_argument("--timeout", type=int, default=240, help="subprocess timeout in seconds")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    repo = Path(args.repo_root).resolve()
    helper_cmd = ["python3", "tools/rust-fixture-regression-list.py", "--summary"]
    harness_cmd = ["bash", "detectors/rust_wave1/test_fixtures/test_detectors.sh"]

    if args.helper_output:
        helper_result = CommandResult(
            command=["<helper-output>", str(args.helper_output)],
            returncode=0,
            stdout=args.helper_output.read_text(encoding="utf-8"),
            stderr="",
        )
    else:
        helper_result = _run(helper_cmd, cwd=repo, timeout=args.timeout)

    if args.harness_output:
        harness_result = CommandResult(
            command=["<harness-output>", str(args.harness_output)],
            returncode=0,
            stdout=args.harness_output.read_text(encoding="utf-8"),
            stderr="",
        )
    else:
        harness_result = _run(harness_cmd, cwd=repo, timeout=args.timeout)

    payload = build_report(
        repo,
        helper_result=helper_result,
        harness_result=harness_result,
        coverage_report=args.coverage_report,
    )
    _write_json(args.json_out if args.json_out.is_absolute() else repo / args.json_out, payload)
    _write_text(args.md_out if args.md_out.is_absolute() else repo / args.md_out, _render_markdown(payload))

    print(
        "rust xfail burndown: "
        f"{payload['status']} "
        f"helper={payload['helper']['detectors']} detectors/"
        f"{payload['helper']['residual_skips']} skips "
        f"harness={payload['harness']['passed']}/{payload['harness']['total']} passed "
        f"xfail={payload['harness']['generated_residual_xfail']}"
    )
    return 0 if payload["status"] != "needs_attention" else 1


if __name__ == "__main__":
    raise SystemExit(main())
