from __future__ import annotations

import argparse
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path


def _load_tool_module():
    root = Path(__file__).resolve().parents[1]
    tool_path = root / "phase-e-outcome-packet.py"
    spec = importlib.util.spec_from_file_location("phase_e_outcome_packet_tool", tool_path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class PhaseEOutcomePacketTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = _load_tool_module()

    def test_build_packet_emits_valid_matched_pair(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            evidence_a = Path(td) / "a.json"
            evidence_b = Path(td) / "b.json"
            evidence_a.write_text("{}\n", encoding="utf-8")
            evidence_b.write_text("{}\n", encoding="utf-8")
            args = argparse.Namespace(
                measurement_window_id="phase-e-2026-06",
                engagement_id="eng-001",
                pair_id="eng-001-ab",
                outcome_observed_at_utc="2026-05-24T00:00:00Z",
                a_ppe=90.0,
                a_frph=80.0,
                a_prqs=70.0,
                a_supporting=60.0,
                b_ppe=50.0,
                b_frph=40.0,
                b_prqs=30.0,
                b_supporting=20.0,
                a_evidence_path=str(evidence_a),
                b_evidence_path=str(evidence_b),
                a_notes=None,
                b_notes=None,
            )
            rows = self.mod.build_packet(args)
            self.assertEqual(2, len(rows))
            self.assertEqual("A", rows[0]["cohort"])
            self.assertEqual("B", rows[1]["cohort"])
            self.assertEqual("eng-001-ab", rows[0]["pair_id"])
            self.assertEqual(rows[0]["engagement_id"], rows[1]["engagement_id"])

    def test_build_packet_rejects_historical_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            evidence = Path(td) / "a.json"
            evidence.write_text("{}\n", encoding="utf-8")
            args = argparse.Namespace(
                measurement_window_id="phase-e-2026-06",
                engagement_id="eng-001",
                pair_id="eng-001-ab",
                outcome_observed_at_utc="2026-05-23T23:59:59Z",
                a_ppe=1.0,
                a_frph=1.0,
                a_prqs=1.0,
                a_supporting=1.0,
                b_ppe=1.0,
                b_frph=1.0,
                b_prqs=1.0,
                b_supporting=1.0,
                a_evidence_path=str(evidence),
                b_evidence_path=str(evidence),
                a_notes=None,
                b_notes=None,
            )
            with self.assertRaisesRegex(ValueError, "must be >= 2026-05-24T00:00:00Z"):
                self.mod.build_packet(args)

    def test_repo_relative_evidence_path_is_accepted_outside_repo_cwd(self) -> None:
        original_cwd = Path.cwd()
        with tempfile.TemporaryDirectory() as td:
            try:
                os.chdir(td)
                accepted = self.mod._require_evidence("docs/PHASE_E_MEASUREMENT_RUNBOOK.md")
            finally:
                os.chdir(original_cwd)
        self.assertEqual("docs/PHASE_E_MEASUREMENT_RUNBOOK.md", accepted)

    def test_non_finite_metrics_are_rejected(self) -> None:
        for value in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(argparse.ArgumentTypeError, "metric values"):
                    self.mod._parse_metric(value)


if __name__ == "__main__":
    unittest.main()
