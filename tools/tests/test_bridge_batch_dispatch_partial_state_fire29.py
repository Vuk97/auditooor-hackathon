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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "bridge_batch_dispatch_partial_state_fire29.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "bridge_batch_dispatch_partial_state_fire29.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "bridge_batch_dispatch_partial_state_fire29.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "bridge-batch-dispatch-partial-state-fire29"


def _load_detector():
    module_name = "bridge_batch_dispatch_partial_state_fire29"
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


class BridgeBatchDispatchPartialStateFire29Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)
        detector_text = _read(DETECTOR_PATH)

        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn("bridge-batch-dispatch-try-catch-continue-partial-state.yaml", detector_text)
        self.assertIn("bridge-proof-domain-bypass-umbrella.yaml", detector_text)
        self.assertIn("bridge_proof_domain.json", detector_text)
        self.assertIn("attack_class: bridge-proof-domain-bypass", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)
        self.assertIn("detector_fixture_smoke_only", detector_text)

    def test_fixture_pair_contains_semantic_contrast(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("BridgeMessage[] calldata messages", positive)
        self.assertIn("require(_verifyProof(root, proof)", positive)
        self.assertIn("consumedMessages[messageId] = true;", positive)
        self.assertIn("creditedAmount[message.recipient] += message.amount;", positive)
        self.assertIn("settledMessages[messageId] = true;", positive)
        self.assertIn("catch {", positive)
        self.assertIn("emit BridgeMessageFailed(messageId);", positive)
        self.assertIn("continue;", positive)

        self.assertIn("catch {", negative)
        self.assertIn("revert BridgeMessageFailed(messageId);", negative)
        self.assertIn("consumedMessages[messageId] = true;", negative)
        self.assertIn("creditedAmount[message.recipient] += message.amount;", negative)
        self.assertIn("settledMessages[messageId] = true;", negative)

        self.assertLess(
            positive.index("consumedMessages[messageId] = true;"),
            positive.index("catch {"),
        )
        self.assertLess(
            negative.index("catch {"),
            negative.index("revert BridgeMessageFailed(messageId);"),
        )

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        positive_findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(positive_findings), 1)
        self.assertEqual(negative_findings, [])
        self.assertEqual(positive_findings[0].detector, DETECTOR_NAME)
        self.assertEqual(positive_findings[0].severity, "High")
        self.assertEqual(positive_findings[0].function, "dispatchBridgeBatch")

        message = positive_findings[0].message
        self.assertIn("consumed or settled marker written before failure is atomic", message)
        self.assertIn("credit or settlement state can be partially applied", message)
        self.assertIn("per-message catch and continue", message)
        self.assertIn("NOT_SUBMIT_READY", message)

    def test_regex_runner_discovers_detector_for_owned_fixture_pair(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        for fixture, expected_hits in ((POSITIVE, 1), (NEGATIVE, 0)):
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
                self.assertNotIn("No custom detectors found", proc.stdout)
                match = re.search(r"total hits:\s*(\d+)", proc.stdout)
                self.assertIsNotNone(match, proc.stdout)
                self.assertEqual(int(match.group(1)), expected_hits, proc.stdout)


if __name__ == "__main__":
    unittest.main()
