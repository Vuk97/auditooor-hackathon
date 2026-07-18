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
    REPO
    / "detectors"
    / "wave17"
    / "bridge_batch_partial_state_or_domain_omission_fire19.py"
)
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "bridge_batch_partial_state_or_domain_omission_fire19.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "bridge_batch_partial_state_or_domain_omission_fire19.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "bridge-batch-partial-state-or-domain-omission-fire19"


def _load_detector():
    module_name = "bridge_batch_partial_state_or_domain_omission_fire19"
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


class BridgeBatchPartialStateOrDomainOmissionFire19Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)
        detector_text = _read(DETECTOR_PATH)
        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn("candidate evidence only", detector_text)

    def test_positive_and_negative_fixture_semantics(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("processed[message.nonce] = true;", positive)
        self.assertIn("credits[message.recipient] += message.amount;", positive)
        self.assertIn("abi.encode(message.recipient, message.amount, message.nonce)", positive)
        self.assertIn("catch {\n                ok = false;\n                continue;", positive)
        self.assertIn("require(msg.value >= executionFee + relayerFee", positive)
        self.assertNotIn("MIN_EXECUTION_FEE", positive)

        self.assertIn("message.sourceChain == EXPECTED_REMOTE_CHAIN", negative)
        self.assertIn("message.destinationChain == block.chainid", negative)
        self.assertIn("BRIDGE_DOMAIN", negative)
        self.assertIn("address(this)", negative)
        self.assertIn("catch {\n                revert CommandFailed();", negative)
        self.assertIn("executionFee >= MIN_EXECUTION_FEE", negative)
        self.assertIn("payload.length > 0", negative)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()
        positive = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(positive), 4)
        self.assertEqual(negative, [])
        self.assertEqual({finding.detector for finding in positive}, {DETECTOR_NAME})
        self.assertEqual(
            {finding.function for finding in positive},
            {"relayBatch", "dispatchCommands", "sendOutbound"},
        )

        messages = "\n".join(finding.message for finding in positive)
        self.assertIn("non-atomic try-catch batch continuation", messages)
        self.assertIn("state write before proof or domain validation", messages)
        self.assertIn("proof digest omits chain or domain binding", messages)
        self.assertIn("outbound message fee floor omitted", messages)

    def test_regex_runner_discovers_detector_for_owned_fixture_pair(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        for fixture, expected_hits in ((POSITIVE, 4), (NEGATIVE, 0)):
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
