#!/usr/bin/env python3
"""iter11 T4 — offline tests for engagement-dashboard + ccia-rust integration.

These tests verify the dashboard's new behavior when a workspace contains a
`ccia_rust_report.json` file (shape produced by `tools/ccia-rust.py`,
iter10 T1). They cover:

  (1) present-report → dashboard surfaces angle + confidence counts,
  (2) absent-report → dashboard omits the section cleanly (no fake zero,
      no "missing report" status string),
  (3) hard-verification → the counts displayed in the markdown match the
      raw JSON input exactly (no silent aggregation bugs).

Offline. Stdlib only. No network. No writes outside the tempdir. The tool
is invoked as a subprocess, same path as `make dashboard`.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "engagement-dashboard.py"


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
    )


def _write_outcomes(ws_dir: Path, rows: list[dict]) -> None:
    ref = ws_dir / "reference"
    ref.mkdir(parents=True, exist_ok=True)
    with (ref / "outcomes.jsonl").open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")


def _write_ccia_rust_report(ws_dir: Path, payload: dict) -> None:
    ws_dir.mkdir(parents=True, exist_ok=True)
    with (ws_dir / "ccia_rust_report.json").open("w", encoding="utf-8") as fh:
        json.dump(payload, fh)


# Shape borrowed from the historical K2 smoke output summarized in
# `agent_outputs/k2_smoke_summary.md` — a small
# synthetic sample that exercises multiple angle classes + both confidence
# levels. Totals: 5 angles, A-AUTH=2 / A-ORACLE=1 / A-ROUNDING=1 /
# A-ARITHMETIC=1 / A-REENT=0; low=3 / medium=2.
SAMPLE_CCIA_RUST = {
    "workspace": "/fake/workspace",
    "lang": "rust",
    "total_files_scanned": 7,
    "angles": [
        {"file": "src/a.rs", "line": 10, "angle": "A-AUTH",
         "confidence": "low", "reason": "r1", "snippet": "s1"},
        {"file": "src/a.rs", "line": 22, "angle": "A-AUTH",
         "confidence": "medium", "reason": "r2", "snippet": "s2"},
        {"file": "src/b.rs", "line": 33, "angle": "A-ORACLE",
         "confidence": "low", "reason": "r3", "snippet": "s3"},
        {"file": "src/b.rs", "line": 44, "angle": "A-ROUNDING",
         "confidence": "medium", "reason": "r4", "snippet": "s4"},
        {"file": "src/c.rs", "line": 55, "angle": "A-ARITHMETIC",
         "confidence": "low", "reason": "r5", "snippet": "s5"},
    ],
}


class EngagementDashboardCciaRustTests(unittest.TestCase):

    def test_dashboard_shows_ccia_rust_counts_when_report_present(self) -> None:
        """Workspace with a ccia_rust_report.json → section present in output."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            audits = tmp_path / "audits"
            projects = tmp_path / "projects"
            audits.mkdir()
            projects.mkdir()

            ws = audits / "ws-rust"
            _write_outcomes(ws, [{
                "report_id": "R-001",
                "outcome": "pending",
                "workspace": "ws-rust",
                "platform": "other",
            }])
            _write_ccia_rust_report(ws, SAMPLE_CCIA_RUST)

            result = _run(
                "--audits-dir", str(audits),
                "--projects-dir", str(projects),
            )

            self.assertEqual(result.returncode, 0, msg=result.stderr)
            # Section header + workspace subheader.
            self.assertIn("## CCIA Rust angles (if available)", result.stdout)
            self.assertIn("### ws-rust", result.stdout)
            # Totals line.
            self.assertIn("Total angles: **5** across 7 files scanned.",
                          result.stdout)
            # Angle classes appear with their counts.
            self.assertIn("| A-AUTH | 2 |", result.stdout)
            self.assertIn("| A-ORACLE | 1 |", result.stdout)
            self.assertIn("| A-ROUNDING | 1 |", result.stdout)
            self.assertIn("| A-ARITHMETIC | 1 |", result.stdout)
            self.assertIn("| A-REENT | 0 |", result.stdout)
            # Confidence breakdown.
            self.assertIn("| low | 3 |", result.stdout)
            self.assertIn("| medium | 2 |", result.stdout)

            # JSON mode carries the same section in the workspace row.
            result_json = _run(
                "--audits-dir", str(audits),
                "--projects-dir", str(projects),
                "--json",
            )
            self.assertEqual(result_json.returncode, 0, msg=result_json.stderr)
            payload = json.loads(result_json.stdout)
            self.assertEqual(len(payload["workspaces"]), 1)
            cr = payload["workspaces"][0]["ccia_rust"]
            self.assertIsNotNone(cr)
            self.assertEqual(cr["total_angles"], 5)
            self.assertEqual(cr["total_files_scanned"], 7)
            self.assertEqual(cr["by_angle"]["A-AUTH"], 2)
            self.assertEqual(cr["by_confidence"]["low"], 3)
            self.assertEqual(cr["by_confidence"]["medium"], 2)

    def test_dashboard_omits_ccia_rust_section_when_report_absent(self) -> None:
        """No report file → no section header, no 'missing' status string.

        Silent absence is the contract (iter11 T4 hard rule): the dashboard
        must NOT emit the "## CCIA Rust angles" heading, must NOT say
        "report absent" / "no ccia-rust report" / any new status string,
        and the JSON workspace row's `ccia_rust` key must be null.
        """
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            audits = tmp_path / "audits"
            projects = tmp_path / "projects"
            audits.mkdir()
            projects.mkdir()

            ws = audits / "ws-empty"
            _write_outcomes(ws, [{
                "report_id": "E-001",
                "outcome": "pending",
                "workspace": "ws-empty",
                "platform": "other",
            }])
            # Intentionally no ccia_rust_report.json.

            result = _run(
                "--audits-dir", str(audits),
                "--projects-dir", str(projects),
            )

            self.assertEqual(result.returncode, 0, msg=result.stderr)
            # Section header absent.
            self.assertNotIn("CCIA Rust angles", result.stdout)
            # No fake "missing" phrasing introduced.
            self.assertNotIn("report absent", result.stdout.lower())
            self.assertNotIn("no ccia-rust report", result.stdout.lower())
            # Baseline dashboard still works (workspace row is there).
            self.assertIn("ws-empty", result.stdout)

            # JSON mode: ccia_rust key is null, section not promoted to any
            # aggregated top-level key.
            result_json = _run(
                "--audits-dir", str(audits),
                "--projects-dir", str(projects),
                "--json",
            )
            self.assertEqual(result_json.returncode, 0, msg=result_json.stderr)
            payload = json.loads(result_json.stdout)
            self.assertIsNone(payload["workspaces"][0]["ccia_rust"])

    def test_dashboard_ccia_rust_counts_match_json_input(self) -> None:
        """Hard-verification: markdown counts match raw JSON aggregation.

        Computes expected counts from the fixture itself and compares to
        the values scraped from the rendered markdown. Guards against
        silent aggregation bugs (off-by-one, mis-keying, swapped angle/
        confidence tallies).
        """
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            audits = tmp_path / "audits"
            projects = tmp_path / "projects"
            audits.mkdir()
            projects.mkdir()

            ws = audits / "ws-hard"
            _write_outcomes(ws, [{
                "report_id": "H-001",
                "outcome": "pending",
                "workspace": "ws-hard",
                "platform": "other",
            }])
            _write_ccia_rust_report(ws, SAMPLE_CCIA_RUST)

            # Expected counts computed from the sample fixture only —
            # never hardcoded a second time.
            angles = SAMPLE_CCIA_RUST["angles"]
            expected_total = len(angles)
            expected_files = SAMPLE_CCIA_RUST["total_files_scanned"]
            expected_by_angle = {
                a: sum(1 for x in angles if x["angle"] == a)
                for a in ("A-AUTH", "A-ORACLE", "A-ROUNDING",
                          "A-REENT", "A-ARITHMETIC")
            }
            expected_by_conf = {
                c: sum(1 for x in angles if x["confidence"] == c)
                for c in ("low", "medium")
            }

            result = _run(
                "--audits-dir", str(audits),
                "--projects-dir", str(projects),
            )
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            md = result.stdout

            # Totals line.
            self.assertIn(
                f"Total angles: **{expected_total}** across "
                f"{expected_files} files scanned.",
                md,
            )
            # Per-angle rows.
            for a, n in expected_by_angle.items():
                self.assertIn(f"| {a} | {n} |", md)
            # Per-confidence rows.
            for c, n in expected_by_conf.items():
                self.assertIn(f"| {c} | {n} |", md)

            # JSON mode must also match.
            result_json = _run(
                "--audits-dir", str(audits),
                "--projects-dir", str(projects),
                "--json",
            )
            self.assertEqual(result_json.returncode, 0, msg=result_json.stderr)
            payload = json.loads(result_json.stdout)
            cr = payload["workspaces"][0]["ccia_rust"]
            self.assertEqual(cr["total_angles"], expected_total)
            self.assertEqual(cr["total_files_scanned"], expected_files)
            self.assertEqual(cr["by_angle"], expected_by_angle)
            self.assertEqual(cr["by_confidence"], expected_by_conf)


if __name__ == "__main__":
    unittest.main()
