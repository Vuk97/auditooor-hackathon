#!/usr/bin/env python3
"""iter8 T5 — offline tests for tools/engagement-dashboard.py.

All four tests run under `tempfile.TemporaryDirectory()` so no real audit
workspace is touched. Tool is invoked as a subprocess, exactly as the
operator or `make engagement-dashboard` target would invoke it.

Offline. Stdlib only. No network. No writes outside the tempdir.
"""

from __future__ import annotations

import json
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


class EngagementDashboardTests(unittest.TestCase):
    def test_dashboard_on_empty_dirs_prints_zero_engagements(self) -> None:
        """Empty audits + projects dirs: exit 0, markdown says '0 of N'."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            audits = tmp_path / "audits"
            projects = tmp_path / "projects"
            audits.mkdir()
            projects.mkdir()

            result = _run(
                "--audits-dir", str(audits),
                "--projects-dir", str(projects),
            )

            self.assertEqual(result.returncode, 0, msg=result.stderr)
            # "0 engagements" appears as "0 of 3" in the gate line. Check
            # both phrasings to be robust to small format edits.
            self.assertIn("0 of 3", result.stdout)
            self.assertIn("Gate: FAIL", result.stdout)

    def test_dashboard_counts_pending_rows_per_workspace(self) -> None:
        """Two workspaces each with 1 pending row → 2 validated engagements."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            audits = tmp_path / "audits"
            projects = tmp_path / "projects"
            audits.mkdir()
            projects.mkdir()

            _write_outcomes(audits / "ws-a", [{
                "report_id": "A-001",
                "outcome": "pending",
                "workspace": "ws-a",
                "platform": "hackenproof",
            }])
            _write_outcomes(audits / "ws-b", [{
                "report_id": "B-001",
                "outcome": "pending",
                "workspace": "ws-b",
                "platform": "cantina",
            }])

            result = _run(
                "--audits-dir", str(audits),
                "--projects-dir", str(projects),
            )

            self.assertEqual(result.returncode, 0, msg=result.stderr)
            # Two workspaces, each validated via ≥1 pending row.
            self.assertIn("2 of 3", result.stdout)
            # Both workspace names appear in the table.
            self.assertIn("ws-a", result.stdout)
            self.assertIn("ws-b", result.stdout)
            # Each shows validated=yes; count two "yes" occurrences in the
            # validated column. Use a narrower anchor on the row body.
            self.assertEqual(result.stdout.count("| yes |"), 2)

    def test_dashboard_json_mode_emits_parseable_json(self) -> None:
        """--json flag produces valid JSON with the expected keys."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            audits = tmp_path / "audits"
            projects = tmp_path / "projects"
            audits.mkdir()
            projects.mkdir()

            _write_outcomes(audits / "ws-json", [{
                "report_id": "J-001",
                "outcome": "pending",
                "workspace": "ws-json",
                "platform": "other",
            }])

            result = _run(
                "--audits-dir", str(audits),
                "--projects-dir", str(projects),
                "--json",
            )

            self.assertEqual(result.returncode, 0, msg=result.stderr)
            payload = json.loads(result.stdout)
            for key in (
                "audits_dir", "projects_dir", "threshold",
                "workspaces", "validated_engagements",
                "needed_to_reach_gate", "gate_state", "status_vocab",
            ):
                self.assertIn(key, payload)
            self.assertEqual(payload["threshold"], 3)
            self.assertEqual(payload["validated_engagements"], 1)
            self.assertEqual(payload["needed_to_reach_gate"], 2)
            self.assertEqual(payload["gate_state"], "FAIL")
            self.assertEqual(len(payload["workspaces"]), 1)
            self.assertEqual(payload["workspaces"][0]["workspace"], "ws-json")
            # Status vocab is exactly the playbook §5 set.
            self.assertEqual(
                payload["status_vocab"],
                ["pending", "accepted", "paid", "duplicate", "rejected"],
            )

    def test_dashboard_threshold_calculation_correct(self) -> None:
        """1 validated engagement + --threshold 3 → '2 more needed'."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            audits = tmp_path / "audits"
            projects = tmp_path / "projects"
            audits.mkdir()
            projects.mkdir()

            _write_outcomes(audits / "solo", [{
                "report_id": "S-001",
                "outcome": "pending",
                "workspace": "solo",
                "platform": "other",
            }])

            result = _run(
                "--audits-dir", str(audits),
                "--projects-dir", str(projects),
                "--threshold", "3",
            )

            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertIn("1 of 3", result.stdout)
            self.assertIn("2 more needed to reach gate", result.stdout)


if __name__ == "__main__":
    unittest.main()
