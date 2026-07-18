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
PATTERN = "inverted-signature-merkle-proofs-access-control-verification-passes-wh"
DETECTOR = (
    ROOT
    / "detectors"
    / "wave_graveyard"
    / "wave13_broken"
    / "inverted_signature_merkle_proofs_access_control_verification_passes_wh.py"
)
SPEC_DRAFT = (
    ROOT
    / "detectors"
    / "_specs"
    / "drafts_glider"
    / f"{PATTERN}.yaml"
)
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = (
    ROOT
    / "detectors"
    / "fixtures"
    / "inverted_signature_merkle_proofs_access_control_verification_passes_wh"
)
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
SMOKE = FIXTURE_DIR / "smoke.json"


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


class InvertedSignatureMerkleProofsAccessControlVerificationPassesWhTest(unittest.TestCase):
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
                "--include-graveyard",
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

    def test_detector_compiles_and_reference_points_at_fixture_pair(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        draft_text = SPEC_DRAFT.read_text(encoding="utf-8")
        reference_text = REFERENCE.read_text(encoding="utf-8")

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("require(!_verify", draft_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)
        self.assertIn("coverage_claim: detector_fixture_smoke_only", reference_text)
        self.assertIn(str(POSITIVE.relative_to(ROOT)), reference_text)
        self.assertIn(str(CLEAN.relative_to(ROOT)), reference_text)

    def test_fixture_pair_and_smoke_record_stay_honest(self) -> None:
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))

        self.assertIn("require(!_verifyWhitelist(proof, leaf)", positive_text)
        self.assertIn("claimed[msg.sender] = true;", positive_text)
        self.assertIn("require(_verifyWhitelist(proof, leaf)", clean_text)
        self.assertNotIn("require(!_verifyWhitelist(proof, leaf)", clean_text)

        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(payload["coverage_claim"], "detector_fixture_smoke_only")
        self.assertIn("source-shape proof only", payload["limitation_note"])

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
