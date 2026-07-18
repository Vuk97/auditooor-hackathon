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
PATTERN = "non-compliant-erc165-self-identification"
DETECTOR = (
    ROOT
    / "detectors"
    / "wave17"
    / "non_compliant_erc165_self_identification.py"
)
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
UNDERSCORE_FIXTURE_DIR = (
    ROOT / "detectors" / "fixtures" / "non_compliant_erc165_self_identification"
)
HYPHEN_FIXTURE_DIR = (
    ROOT / "detectors" / "fixtures" / "non-compliant-erc165-self-identification"
)
POSITIVE = UNDERSCORE_FIXTURE_DIR / "positive.sol"
CLEAN = UNDERSCORE_FIXTURE_DIR / "clean.sol"
SMOKE = UNDERSCORE_FIXTURE_DIR / "smoke.json"
HYPHEN_SMOKE = HYPHEN_FIXTURE_DIR / "smoke.json"


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


class NonCompliantErc165SelfIdentificationTest(unittest.TestCase):
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

    def test_detector_reference_and_fixture_metadata_stay_honest(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        reference_text = REFERENCE.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))
        hyphen_payload = json.loads(HYPHEN_SMOKE.read_text(encoding="utf-8"))

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)
        self.assertIn("supportsInterface omits explicit ERC165", detector_text)

        self.assertIn("coverage_claim: detector_fixture_smoke_only", reference_text)
        self.assertIn("submission_posture: NOT_SUBMIT_READY", reference_text)
        self.assertIn(
            "vuln: detectors/fixtures/non_compliant_erc165_self_identification/positive.sol",
            reference_text,
        )
        self.assertIn(
            "clean: detectors/fixtures/non_compliant_erc165_self_identification/clean.sol",
            reference_text,
        )

        self.assertIn("return interfaceId == type(IERC721Like).interfaceId;", positive_text)
        self.assertNotIn("type(IERC165).interfaceId", positive_text)
        self.assertIn("type(IERC165).interfaceId", clean_text)

        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(payload["coverage_claim"], "detector_fixture_smoke_only")
        self.assertIn("source-shape proof only", payload["limitation_note"])

        self.assertEqual(hyphen_payload["positive_hits"], 1)
        self.assertEqual(hyphen_payload["clean_hits"], 0)
        self.assertEqual(
            (HYPHEN_FIXTURE_DIR / "positive.sol").read_text(encoding="utf-8"),
            positive_text,
        )
        self.assertEqual(
            (HYPHEN_FIXTURE_DIR / "clean.sol").read_text(encoding="utf-8"),
            clean_text,
        )

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
