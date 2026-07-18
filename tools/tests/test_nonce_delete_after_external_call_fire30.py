from __future__ import annotations

import importlib.util
import os
import py_compile
import re
import subprocess
import sys
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
DETECTOR_PATH = (
    REPO / "detectors" / "wave17" / "nonce_delete_after_external_call_fire30.py"
)
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "nonce_delete_after_external_call_fire30.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "nonce_delete_after_external_call_fire30.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "nonce-delete-after-external-call-fire30"


def _load_detector():
    module_name = "nonce_delete_after_external_call_fire30"
    if module_name in sys.modules:
        return sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(module_name, DETECTOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class NonceDeleteAfterExternalCallFire30Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_positive_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        clean_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(findings), 3)
        self.assertEqual(clean_findings, [])
        self.assertEqual({finding.detector for finding in findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in findings}, {"Medium"})
        self.assertEqual(
            {finding.function for finding in findings},
            {"executeWithNonce", "claimProof", "finalizeCommitment"},
        )

        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("reads replay key `nonces` before external control flow", messages)
        self.assertIn("reads replay key `consumedProof` before external control flow", messages)
        self.assertIn("reads replay key `commitments` before external control flow", messages)
        self.assertIn("consumes or deletes it only after that boundary", messages)

    def test_fixture_pair_contains_ordering_contrasts(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertRegex(
            positive,
            r"target\.call\(payload\);[\s\S]*nonces\[msg\.sender\] = nonce \+ 1;",
        )
        self.assertRegex(
            positive,
            r"IERC20Fire30\(token\)\.safeTransfer\(to, amount\);"
            r"[\s\S]*consumedProof\[proofHash\] = true;",
        )
        self.assertRegex(
            positive,
            r"IFinalizeReceiverFire30\(receiver\)\.onFinalize\(key\);"
            r"[\s\S]*delete commitments\[key\];",
        )

        self.assertRegex(
            negative,
            r"nonces\[msg\.sender\] = nonce \+ 1;[\s\S]*target\.call\(payload\);",
        )
        self.assertRegex(
            negative,
            r"consumedProof\[proofHash\] = true;"
            r"[\s\S]*IERC20Fire30Clean\(token\)\.safeTransfer\(to, amount\);",
        )
        self.assertRegex(
            negative,
            r"delete commitments\[key\];"
            r"[\s\S]*IFinalizeReceiverFire30Clean\(receiver\)\.onFinalize\(key\);",
        )
        self.assertIn("external nonReentrant", negative)
        self.assertIn("metrics[metricId] = true;", negative)

    def test_regex_runner_discovers_detector_for_fixture_pair(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        for fixture, expected_hits in ((POSITIVE, 3), (NEGATIVE, 0)):
            with self.subTest(fixture=fixture.name):
                proc = subprocess.run(
                    [
                        sys.executable,
                        str(RUNNER),
                        str(fixture),
                        "--detector",
                        DETECTOR_NAME,
                        "--no-manifest",
                    ],
                    cwd=REPO,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(proc.returncode, 0, proc.stdout)
                match = re.search(r"total hits:\s*(\d+)", proc.stdout)
                self.assertIsNotNone(match, proc.stdout)
                self.assertEqual(int(match.group(1)), expected_hits, proc.stdout)


if __name__ == "__main__":
    unittest.main()
