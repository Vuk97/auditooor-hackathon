#!/usr/bin/env python3
"""Emit the Rust fixture regression detector list.

The static shell list is the compatibility baseline.  The coverage report is
the source of truth for fixture-backed detectors that are not yet listed there.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


DEFAULT_REPORT = Path("reports/rust_detector_coverage_2026-05-05.json")
HARNESS = Path("detectors/rust_wave1/test_fixtures/test_detectors.sh")
FIXTURES = Path("detectors/rust_wave1/test_fixtures")
DETECTORS = Path("detectors/rust_wave1")


def parse_static_harness(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    match = re.search(r"^DETECTORS=\(\n(?P<body>.*?)^\)", text, flags=re.M | re.S)
    if not match:
        raise ValueError(f"could not find DETECTORS array in {path}")

    detectors: list[str] = []
    for line in match.group("body").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        detectors.append(line.split()[0])
    return detectors


def _report_candidates(report: dict) -> list[dict]:
    rows = report.get("per_detector")
    if isinstance(rows, list):
        return [row for row in rows if isinstance(row, dict)]
    rows = report.get("missing_runner_hook", {}).get("detectors")
    if isinstance(rows, list):
        return [row for row in rows if isinstance(row, dict)]
    return []


def residual_skips(report: dict, included: set[str] | list[str] | tuple[str, ...] | None = None) -> list[str]:
    included_set = set(included or [])
    skipped: list[str] = []
    for row in _report_candidates(report):
        detector_id = str(row.get("detector_id", ""))
        if not detector_id:
            continue
        if detector_id in included_set:
            continue
        if row.get("fixture_pair_present") is not True:
            skipped.append(detector_id)
        elif row.get("nested_detector") is True:
            skipped.append(detector_id)
        elif row.get("detector_group") not in (None, "rust_wave1"):
            skipped.append(detector_id)
    return skipped


def build_regression_list(repo: Path, report_path: Path) -> tuple[list[str], list[str]]:
    harness = repo / HARNESS
    fixtures = repo / FIXTURES
    detectors_dir = repo / DETECTORS
    detector_list = parse_static_harness(harness)
    seen = set(detector_list)

    if not report_path.exists():
        return detector_list, []

    report = json.loads(report_path.read_text(encoding="utf-8"))
    for row in _report_candidates(report):
        detector_id = str(row.get("detector_id", ""))
        if not detector_id or detector_id in seen:
            continue
        if row.get("fixture_pair_present") is not True:
            continue
        if row.get("nested_detector") is True:
            continue
        if row.get("detector_group") not in (None, "rust_wave1"):
            continue
        if not (detectors_dir / f"{detector_id}.py").exists():
            continue
        if not (fixtures / f"{detector_id}_positive.rs").exists():
            continue
        if not (fixtures / f"{detector_id}_negative.rs").exists():
            continue
        detector_list.append(detector_id)
        seen.add(detector_id)

    return detector_list, residual_skips(report, seen)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--report", type=Path, default=None)
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args(argv)

    repo = args.repo.resolve()
    report = args.report if args.report is not None else repo / DEFAULT_REPORT
    if not report.is_absolute():
        report = repo / report

    try:
        detectors, skipped = build_regression_list(repo, report)
    except Exception as exc:
        print(f"[err] {exc}", file=sys.stderr)
        return 2

    if args.summary:
        print(f"detectors={len(detectors)}")
        print(f"residual_skips={len(skipped)}")
        return 0

    for detector in detectors:
        print(detector)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
