#!/usr/bin/env python3
"""Tests for tools/fp-calibration.sh --smoke and the smoke manifest emission.

P1-4 burn-down. Stdlib-only, hermetic. Confirms that ``fp-calibration.sh
--smoke`` runs against the in-tree fixture corpus
(``tests/fixtures/fp_calibration_corpus/``) and emits a JSON manifest with
the expected schema, even when the underlying detector chain skips (CI
might not have a Solidity toolchain installed, and that is fine — smoke
proves wiring, not detector quality).
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SH_PATH = REPO_ROOT / "tools" / "fp-calibration.sh"
CORPUS_PATH = REPO_ROOT / "tests" / "fixtures" / "fp_calibration_corpus"


class FpCalibrationSmokeTest(unittest.TestCase):
    def test_smoke_emits_manifest(self) -> None:
        self.assertTrue(SH_PATH.exists(), f"{SH_PATH} missing")
        self.assertTrue(CORPUS_PATH.exists(), f"{CORPUS_PATH} missing")
        # The fixture corpus must contain at least one .sol file.
        sols = list(CORPUS_PATH.rglob("*.sol"))
        self.assertGreaterEqual(
            len(sols), 1, "smoke corpus should ship with at least 1 .sol"
        )

        with tempfile.TemporaryDirectory(prefix="fpcal-smoke-") as tmp:
            log_dir = Path(tmp) / "log"
            manifest_out = Path(tmp) / "smoke_manifest.json"
            env = os.environ.copy()
            env["LOG_DIR"] = str(log_dir)
            env["SMOKE_MANIFEST_OUT"] = str(manifest_out)
            # Force a deterministic tier filter so the smoke output does
            # not vary on the environment-default.
            env["TIER"] = "S,E"
            proc = subprocess.run(
                ["bash", str(SH_PATH), "--smoke"],
                env=env,
                capture_output=True,
                text=True,
                cwd=str(REPO_ROOT),
                timeout=120,
            )
            self.assertEqual(
                proc.returncode,
                0,
                msg=(
                    f"fp-calibration.sh --smoke failed: rc={proc.returncode}\n"
                    f"stdout=\n{proc.stdout}\nstderr=\n{proc.stderr}"
                ),
            )
            self.assertTrue(
                manifest_out.exists(),
                f"smoke manifest not emitted at {manifest_out}",
            )
            payload = json.loads(manifest_out.read_text(encoding="utf-8"))
            self.assertEqual(
                payload["schema_version"],
                "auditooor.fp_calibration_smoke.v1",
            )
            self.assertEqual(payload["mode"], "smoke")
            self.assertEqual(payload["corpus_root"], str(CORPUS_PATH))
            self.assertEqual(
                payload["corpus_file_count"], len(sols)
            )
            self.assertIsInstance(payload["corpus_hash"], str)
            self.assertEqual(len(payload["corpus_hash"]), 16)
            self.assertIsInstance(payload["detectors_executed"], list)
            self.assertIsInstance(payload["hits_by_detector"], dict)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
