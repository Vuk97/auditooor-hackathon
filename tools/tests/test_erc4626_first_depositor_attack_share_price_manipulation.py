from __future__ import annotations

import json
import os
import py_compile
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
PATTERN = "erc4626-first-depositor-attack-share-price-manipulation"
DETECTOR = (
    ROOT
    / "detectors"
    / "wave17"
    / "erc4626_first_depositor_attack_share_price_manipulation.py"
)
SPEC_DRAFT = (
    ROOT
    / "detectors"
    / "_specs"
    / "drafts_glider"
    / f"{PATTERN}.yaml"
)
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "erc4626_first_depositor_attack_share_price_manipulation"
POSITIVE = FIXTURE_DIR / "erc4626_first_depositor_attack_share_price_manipulation_vulnerable.sol"
CLEAN = FIXTURE_DIR / "erc4626_first_depositor_attack_share_price_manipulation_clean.sol"
MANIFEST = FIXTURE_DIR / "manifest.json"
SMOKE = FIXTURE_DIR / "smoke.json"

def _python_with_slither() -> str | None:
    candidates = [
        os.environ.get("SLITHER_PYTHON"),
        sys.executable,
        "/opt/homebrew/opt/python@3.13/bin/python3.13",
        "/opt/homebrew/bin/python3.13",
        "python3",
    ]
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        try:
            proc = subprocess.run(
                [candidate, "-c", "import slither; import slither.detectors.abstract_detector"],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode == 0:
            return candidate
    return None


class Erc4626FirstDepositorAttackSharePriceManipulationTest(unittest.TestCase):
    def _hits(self, fixture: Path) -> int:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [
                slither_python,
                str(RUNNER),
                "--tier=ALL",
                str(fixture),
                PATTERN,
            ],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertNotIn("No custom detectors found", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_detector_spec_and_reference_stay_aligned(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        draft_text = SPEC_DRAFT.read_text(encoding="utf-8")
        reference_text = REFERENCE.read_text(encoding="utf-8")

        self.assertIn('ARGUMENT = "erc4626-first-depositor-attack-share-price-manipulation"', detector_text)
        self.assertIn("bootstrap|initialDeposit|firstDeposit|seed", detector_text)
        self.assertIn("totalSupply|totalShares|shareSupply|totalAssets|managedAssets|assetBalance", detector_text)
        self.assertIn("bootstrap|initialDeposit|firstDeposit|seed", draft_text)
        self.assertIn(
            "detectors/fixtures/erc4626_first_depositor_attack_share_price_manipulation/erc4626_first_depositor_attack_share_price_manipulation_vulnerable.sol",
            reference_text,
        )
        self.assertIn(
            "detectors/fixtures/erc4626_first_depositor_attack_share_price_manipulation/erc4626_first_depositor_attack_share_price_manipulation_clean.sol",
            reference_text,
        )

    def test_fixture_pair_manifest_points_at_live_wave17_detector(self) -> None:
        payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertTrue(payload["advisory_only"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(payload["detector_path"], str(DETECTOR.relative_to(ROOT)))
        self.assertEqual(payload["positive_fixture_path"], str(POSITIVE.relative_to(ROOT)))
        self.assertEqual(payload["clean_fixture_path"], str(CLEAN.relative_to(ROOT)))
        self.assertIn("source-shape approximation", payload["operator_note"])
        self.assertNotIn("/opt/homebrew/opt/python@3.13/bin/python3.13", payload["shell_command"])
        self.assertIn("python3 detectors/run_custom.py", payload["shell_command"])

    def test_smoke_record_keeps_not_submit_ready_posture(self) -> None:
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "passed_vulnerable_clean_smoke")
        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["detector_path"], str(DETECTOR.relative_to(ROOT)))
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)
        self.assertNotIn("--include-graveyard", payload["positive_command"])
        self.assertNotIn("--include-graveyard", payload["clean_command"])
        self.assertNotIn("/opt/homebrew/opt/python@3.13/bin/python3.13", payload["positive_command"])
        self.assertNotIn("/opt/homebrew/opt/python@3.13/bin/python3.13", payload["clean_command"])
        self.assertIn("python3 detectors/run_custom.py", payload["positive_command"])
        self.assertIn("python3 detectors/run_custom.py", payload["clean_command"])

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertGreaterEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
