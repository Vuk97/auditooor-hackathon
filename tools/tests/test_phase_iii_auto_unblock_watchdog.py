#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "phase-iii-auto-unblock-watchdog.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("phase_iii_auto_unblock_watchdog", TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {TOOL}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_json(path: Path, payload: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def write_jsonl(path: Path, rows: list[dict]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n", encoding="utf-8")
    return path


class PhaseIIIAutoUnblockWatchdogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = load_tool()

    def _prqs(self, root: Path) -> Path:
        return write_json(
            root / "prqs.json",
            {
                "schema": "auditooor.hb_prqs_comparator_matched_cohort.v1",
                "gate1_prqs_state": "decisive",
                "verdict": "decisive_prqs_no_regression",
                "comparator": {
                    "matched_pair_count": 6,
                    "cohort_a": {"average_score": 44.0},
                    "cohort_b": {"average_score": 30.167},
                    "average_delta_a_minus_b": 13.833,
                    "max_pair_regression_drop_points": 0,
                    "pairs_exceeding_regression_limit": [],
                },
            },
        )

    def _evidence(self, root: Path, *, engagement_id: str, pair_id: str, cohort: str) -> str:
        return str(write_json(
            root / "evidence" / engagement_id / f"{pair_id}-{cohort}.json",
            {"engagement_id": engagement_id, "pair_id": pair_id, "cohort": cohort},
        ))

    def _row(self, *, engagement_id: str, pair_id: str, cohort: str, evidence: str) -> dict:
        return {
            "schema": "auditooor.phase_e_ab_outcome_row.v1",
            "measurement_window_id": "phase-e-window-test",
            "engagement_id": engagement_id,
            "pair_id": pair_id,
            "cohort": cohort,
            "outcome_observed_at_utc": "2026-06-01T00:00:00Z",
            "metrics": {"ppe": 0.7, "frph": 0.6, "prqs": 0.75, "supporting": 0.6},
            "evidence_paths": [evidence],
        }

    def test_blocked_when_future_pair_and_engagement_thresholds_not_met(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            rows: list[dict] = []
            for idx in range(3):
                engagement_id = f"eng-{idx}"
                pair_id = f"pair-{idx}"
                rows.append(self._row(
                    engagement_id=engagement_id,
                    pair_id=pair_id,
                    cohort="A",
                    evidence=self._evidence(root, engagement_id=engagement_id, pair_id=pair_id, cohort="A"),
                ))
                rows.append(self._row(
                    engagement_id=engagement_id,
                    pair_id=pair_id,
                    cohort="B",
                    evidence=self._evidence(root, engagement_id=engagement_id, pair_id=pair_id, cohort="B"),
                ))
            args = type("Args", (), {
                "measurement_summary": str(root / "missing-summary.json"),
                "phase_e_rows": str(write_jsonl(root / "phase_e_rows.jsonl", rows)),
                "prqs_comparator": str(self._prqs(root)),
                "required_future_engagements": 4,
                "required_valid_future_matched_pairs": None,
            })()
            payload = self.tool.evaluate(args)

        self.assertEqual(payload["phase_iii"]["III.4"]["status"], "blocked")
        self.assertEqual(payload["phase_iii"]["III.5"]["status"], "blocked")
        self.assertFalse(payload["auto_unblock_summary"]["all_phase_iii_unblocked"])
        self.assertIn("insufficient_valid_future_matched_pairs", payload["phase_e_readiness"]["blockers"])
        self.assertIn("insufficient_valid_future_matched_engagements", payload["phase_e_readiness"]["blockers"])

    def test_auto_unblocks_iii4_and_iii5_when_thresholds_are_met(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            rows: list[dict] = []
            for idx in range(4):
                engagement_id = f"eng-{idx}"
                pair_id = f"pair-{idx}"
                rows.append(self._row(
                    engagement_id=engagement_id,
                    pair_id=pair_id,
                    cohort="A",
                    evidence=self._evidence(root, engagement_id=engagement_id, pair_id=pair_id, cohort="A"),
                ))
                rows.append(self._row(
                    engagement_id=engagement_id,
                    pair_id=pair_id,
                    cohort="B",
                    evidence=self._evidence(root, engagement_id=engagement_id, pair_id=pair_id, cohort="B"),
                ))
            args = type("Args", (), {
                "measurement_summary": str(root / "missing-summary.json"),
                "phase_e_rows": str(write_jsonl(root / "phase_e_rows.jsonl", rows)),
                "prqs_comparator": str(self._prqs(root)),
                "required_future_engagements": 4,
                "required_valid_future_matched_pairs": None,
            })()
            payload = self.tool.evaluate(args)

        self.assertEqual(payload["phase_iii"]["III.4"]["status"], "auto_unblocked")
        self.assertEqual(payload["phase_iii"]["III.5"]["status"], "auto_unblocked")
        self.assertTrue(payload["auto_unblock_summary"]["all_phase_iii_unblocked"])
        self.assertEqual(payload["phase_e_readiness"]["blockers"], [])

    def test_cli_emits_machine_readable_json(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            rows: list[dict] = []
            for idx in range(4):
                engagement_id = f"eng-{idx}"
                pair_id = f"pair-{idx}"
                rows.append(self._row(
                    engagement_id=engagement_id,
                    pair_id=pair_id,
                    cohort="A",
                    evidence=self._evidence(root, engagement_id=engagement_id, pair_id=pair_id, cohort="A"),
                ))
                rows.append(self._row(
                    engagement_id=engagement_id,
                    pair_id=pair_id,
                    cohort="B",
                    evidence=self._evidence(root, engagement_id=engagement_id, pair_id=pair_id, cohort="B"),
                ))
            rows_path = write_jsonl(root / "phase_e_rows.jsonl", rows)
            prqs_path = self._prqs(root)
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--phase-e-rows",
                    str(rows_path),
                    "--prqs-comparator",
                    str(prqs_path),
                    "--json",
                ],
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["schema"], "auditooor.phase_iii_auto_unblock_watchdog.v1")
        self.assertIn("phase_iii", payload)
        self.assertIn("III.4", payload["phase_iii"])
        self.assertIn("III.5", payload["phase_iii"])
        self.assertTrue(payload["phase_iii"]["III.4"]["auto_unblock"])
        self.assertTrue(payload["phase_iii"]["III.5"]["auto_unblock"])

    def test_phase_e_rows_use_default_prqs_when_arg_is_omitted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            rows: list[dict] = []
            for idx in range(4):
                engagement_id = f"eng-{idx}"
                pair_id = f"pair-{idx}"
                rows.append(self._row(
                    engagement_id=engagement_id,
                    pair_id=pair_id,
                    cohort="A",
                    evidence=self._evidence(root, engagement_id=engagement_id, pair_id=pair_id, cohort="A"),
                ))
                rows.append(self._row(
                    engagement_id=engagement_id,
                    pair_id=pair_id,
                    cohort="B",
                    evidence=self._evidence(root, engagement_id=engagement_id, pair_id=pair_id, cohort="B"),
                ))
            rows_path = write_jsonl(root / "phase_e_rows.jsonl", rows)
            original_default = self.tool.DEFAULT_PRQS_COMPARATOR
            expected_prqs_path = self._prqs(root).resolve()
            self.tool.DEFAULT_PRQS_COMPARATOR = expected_prqs_path
            try:
                args = type("Args", (), {
                    "measurement_summary": str(root / "missing-summary.json"),
                    "phase_e_rows": str(rows_path),
                    "prqs_comparator": "",
                    "required_future_engagements": 4,
                    "required_valid_future_matched_pairs": None,
                })()
                payload = self.tool.evaluate(args)
            finally:
                self.tool.DEFAULT_PRQS_COMPARATOR = original_default

        self.assertEqual(payload["inputs"]["prqs_comparator"], str(expected_prqs_path))
        self.assertTrue(payload["auto_unblock_summary"]["all_phase_iii_unblocked"])


if __name__ == "__main__":
    unittest.main()
