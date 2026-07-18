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
PATTERN = "public-helper-mutates-reputation-index-per-address"
DETECTOR = ROOT / "detectors" / "wave17" / "public_helper_mutates_reputation_index_per_address.py"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "public_helper_mutates_reputation_index_per_address"
MIRROR_DIR = ROOT / "detectors" / "fixtures" / PATTERN
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
SMOKE = FIXTURE_DIR / "smoke.json"
MIRROR_POSITIVE = MIRROR_DIR / "positive.sol"
MIRROR_CLEAN = MIRROR_DIR / "clean.sol"
MIRROR_SMOKE = MIRROR_DIR / "smoke.json"


def _python_with_slither() -> str | None:
    candidates = [
        os.environ.get("SLITHER_PYTHON"),
        sys.executable,
        "/opt/homebrew/opt/python@3.13/bin/python3.13",
        "/opt/homebrew/bin/python3.13",
    ]
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        try:
            probe = subprocess.run(
                [candidate, "-c", "import slither; import slither.detectors.abstract_detector"],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if probe.returncode == 0:
            return candidate
    return None


class PublicHelperMutatesReputationIndexPerAddressTest(unittest.TestCase):
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
        self.assertIn(PATTERN, proc.stdout)
        self.assertNotIn("No custom detectors found", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_detector_reference_and_fixture_metadata(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        reference_text = REFERENCE.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))
        mirror_payload = json.loads(MIRROR_SMOKE.read_text(encoding="utf-8"))

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("contract.has_state_var_matching", detector_text)
        self.assertIn("function.writes_storage_matching", detector_text)
        self.assertIn("function.has_param_name_matching", detector_text)
        self.assertIn("onlyRole", detector_text)

        self.assertIn(str(POSITIVE.relative_to(ROOT)), reference_text)
        self.assertIn(str(CLEAN.relative_to(ROOT)), reference_text)
        self.assertIn("coverage_claim: detector_fixture_smoke_only", reference_text)
        self.assertIn("submission_posture: NOT_SUBMIT_READY", reference_text)
        self.assertIn("fixture_mirrors:", reference_text)

        self.assertIn("function _addCredIdPerAddress(uint256 credId, address sender_) public", positive_text)
        self.assertIn("_credIdsPerAddress[sender_].push(credId);", positive_text)
        self.assertNotIn("msg.sender == sender_", positive_text)

        self.assertIn("function _addCredIdPerAddress(uint256 credId, address sender_) public", clean_text)
        self.assertIn('require(msg.sender == sender_, "self only");', clean_text)
        self.assertIn("_credIdIndexPerAddress[sender_][credId]", clean_text)

        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["status"], "passed_vulnerable_clean_smoke")
        self.assertEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)
        self.assertEqual(payload["coverage_claim"], "detector_fixture_smoke_only")
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertIn("public per-address reputation index helper", payload["limitation_note"])

        self.assertEqual(POSITIVE.read_text(encoding="utf-8"), MIRROR_POSITIVE.read_text(encoding="utf-8"))
        self.assertEqual(CLEAN.read_text(encoding="utf-8"), MIRROR_CLEAN.read_text(encoding="utf-8"))
        self.assertEqual(mirror_payload["pattern"], PATTERN)
        self.assertEqual(mirror_payload["positive_hits"], 1)
        self.assertEqual(mirror_payload["clean_hits"], 0)
        self.assertEqual(mirror_payload["submission_posture"], "NOT_SUBMIT_READY")

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
