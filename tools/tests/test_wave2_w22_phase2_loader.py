"""
Tests for the Wave-2 W2.2 Phase-2 detector loader + smoke driver.

The loader lives at: tools/audit/wave2_w22_detector_loader.py
The smoke driver lives at: tools/audit/wave2_w22_phase2_smoke.py
The Phase-2 roster lives at: tools/audit/detector_previews/wave2_w22_phase2_roster.json

These tests are structural + behavioural. They use synthetic fixture
trees marked `synthetic_fixture: true` in their tmpdir bodies to avoid
coupling to any real workspace state. The fixtures are NOT representative
of real audit work; they exist only to validate loader + smoke wiring.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.audit import wave2_w22_detector_loader as loader  # noqa: E402
from tools.audit import wave2_w22_phase2_smoke as smoke_mod  # noqa: E402


SYNTHETIC_MARKER = "synthetic_fixture: true"


class Wave2W22Phase2LoaderTests(unittest.TestCase):
    """Structural and behavioural contract tests for the loader."""

    def setUp(self) -> None:
        # Force-clear env flags so each test starts from a known baseline.
        for flag in (loader.PHASE1_ENV_FLAG, loader.PHASE2_ENV_FLAG):
            if flag in os.environ:
                del os.environ[flag]

    # ---- loader: env flag handling ----

    def test_01_both_flags_off_returns_empty_active_set(self) -> None:
        """Default OFF for both env flags must return no active detectors."""
        env: dict[str, str] = {}
        self.assertFalse(loader.phase1_enabled(env))
        self.assertFalse(loader.phase2_enabled(env))
        self.assertEqual(loader.load_active_detectors(env), [])
        status = loader.loader_status(env)
        self.assertEqual(status["active_detector_count"], 0)

    def test_02_phase1_only_returns_twenty_detectors(self) -> None:
        """Phase-1 ON, Phase-2 OFF should yield exactly the 20 phase-1 entries."""
        env = {loader.PHASE1_ENV_FLAG: "1"}
        detectors = loader.load_active_detectors(env)
        self.assertEqual(len(detectors), 20, "phase-1 roster must be exactly 20")
        # All phase-1 ids start with `w22_` and none with `w22p2_`.
        for det in detectors:
            self.assertTrue(det["detector_id"].startswith("w22_"))
            self.assertFalse(det["detector_id"].startswith("w22p2_"))

    def test_03_phase2_on_alone_does_not_load_anything(self) -> None:
        """Phase-2 implies Phase-1; without Phase-1 the active set is empty."""
        env = {loader.PHASE2_ENV_FLAG: "true"}
        self.assertFalse(loader.phase1_enabled(env))
        self.assertTrue(loader.phase2_enabled(env))
        self.assertEqual(loader.load_active_detectors(env), [])

    def test_04_phase1_and_phase2_concatenated_count(self) -> None:
        """Phase-1 + Phase-2 ON should yield p1 + p2 detector count."""
        env = {
            loader.PHASE1_ENV_FLAG: "yes",
            loader.PHASE2_ENV_FLAG: "yes",
        }
        detectors = loader.load_active_detectors(env)
        p1 = loader.load_phase1_roster()
        p2 = loader.load_phase2_roster()
        self.assertEqual(len(detectors), len(p1) + len(p2))
        # Phase-2 entries must all have the w22p2_ prefix per the roster
        # convention; phase-1 entries must not.
        p1_ids = {d["detector_id"] for d in p1}
        p2_ids = {d["detector_id"] for d in p2}
        self.assertTrue(all(i.startswith("w22p2_") for i in p2_ids))
        self.assertTrue(p1_ids.isdisjoint(p2_ids), "phase-1 and phase-2 ids must not overlap")

    def test_05_loader_status_envelope_shape(self) -> None:
        """loader_status emits a stable schema with all required fields."""
        env = {loader.PHASE1_ENV_FLAG: "1", loader.PHASE2_ENV_FLAG: "1"}
        status = loader.loader_status(env)
        required = {
            "schema",
            "phase1_env_flag",
            "phase1_enabled",
            "phase2_env_flag",
            "phase2_enabled",
            "phase1_roster_path",
            "phase2_roster_path",
            "phase1_detector_count",
            "phase2_detector_count",
            "active_detector_count",
        }
        self.assertTrue(required.issubset(status.keys()))
        self.assertEqual(status["schema"], "auditooor.wave2_w22_loader_status.v1")
        self.assertEqual(status["phase1_env_flag"], "AUDITOOOR_W22_PHASE1_ENABLED")
        self.assertEqual(status["phase2_env_flag"], "AUDITOOOR_W22_PHASE2_ENABLED")
        self.assertEqual(
            status["active_detector_count"],
            status["phase1_detector_count"] + status["phase2_detector_count"],
        )

    # ---- smoke driver behaviour ----

    def test_06_smoke_off_returns_zero_total_hits(self) -> None:
        """With env flags OFF, the smoke driver must report zero evaluations."""
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            (workspace / "src").mkdir()
            (workspace / "src" / "Sample.sol").write_text(
                f"// {SYNTHETIC_MARKER}\n"
                "contract Sample { function foo() public payable { msg.sender.call{value: 1}(\"\"); } }\n",
                encoding="utf-8",
            )
            result = smoke_mod.run_smoke(workspace, env={})
            self.assertEqual(result["total_hit_files"], 0)
            self.assertEqual(result["detector_count_evaluated"], 0)
            self.assertEqual(result["loader_status"]["active_detector_count"], 0)

    def test_07_smoke_phase2_on_fires_on_synthetic_solidity(self) -> None:
        """Phase-2 ON should detect the `.call{value:` literal in a tmp fixture."""
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            (workspace / "src").mkdir()
            (workspace / "src" / "Sample.sol").write_text(
                f"// {SYNTHETIC_MARKER}\n"
                "contract Sample {\n"
                "  function foo() public {\n"
                "    payable(msg.sender).call{value: 1}(\"\");\n"
                "    tx.origin == msg.sender;\n"
                "  }\n"
                "}\n",
                encoding="utf-8",
            )
            env = {
                loader.PHASE1_ENV_FLAG: "1",
                loader.PHASE2_ENV_FLAG: "1",
            }
            result = smoke_mod.run_smoke(workspace, env=env)
            self.assertGreater(result["total_hit_files"], 0)
            self.assertEqual(result["detector_count_evaluated"], 40)
            # Confirm a Phase-2 detector fired (unchecked_call_value or tx_origin).
            phase2_hits = [
                row
                for row in result["per_detector_hits"]
                if row["detector_id"].startswith("w22p2_") and row["hit_files"] > 0
            ]
            self.assertGreater(len(phase2_hits), 0)


if __name__ == "__main__":
    unittest.main()
