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
    / "bridge_proof_domain_batch_dispatch_fire23.py"
)
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "bridge_proof_domain_batch_dispatch_fire23.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "bridge_proof_domain_batch_dispatch_fire23.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "bridge-proof-domain-batch-dispatch-fire23"


def _load_detector():
    module_name = "bridge_proof_domain_batch_dispatch_fire23"
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


class BridgeProofDomainBatchDispatchFire23Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)
        detector_text = _read(DETECTOR_PATH)
        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn("candidate evidence only", detector_text)
        self.assertIn("weak consume key", detector_text)

    def test_fixture_pair_contains_semantic_contrast(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("BridgeMessage[] calldata messages", positive)
        self.assertIn("keccak256(abi.encode(root, msg_.nonce))", positive)
        self.assertIn("consumedMessages[consumedKey] = true;", positive)
        self.assertIn("msg_.destinationDomain != LOCAL_DOMAIN", positive)
        self.assertIn("continue;", positive)
        self.assertIn("if (!success)", positive)
        self.assertIn("Fire23Proof.verify(proof, root, leaf)", positive)
        self.assertNotIn("BRIDGE_DOMAIN", positive)

        self.assertIn("BRIDGE_DOMAIN", negative)
        self.assertIn("uint32(block.chainid)", negative)
        self.assertIn("address(this)", negative)
        self.assertIn("msg_.sourceDomain", negative)
        self.assertIn("msg_.destinationDomain", negative)
        self.assertIn("msg_.routeId", negative)
        self.assertIn("revert WrongDomain();", negative)
        self.assertIn("revert DispatchFailed();", negative)
        self.assertIn("consumedMessages[consumedKey] = true;", negative)

        self.assertLess(
            positive.index("consumedMessages[consumedKey] = true;"),
            positive.index("msg_.destinationDomain != LOCAL_DOMAIN"),
        )
        self.assertLess(
            negative.index("Fire23ProofSafe.verify(proof, root, leaf)"),
            negative.index("consumedMessages[consumedKey] = true;"),
        )

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()
        positive = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(positive), 1)
        self.assertEqual(negative, [])
        self.assertEqual(positive[0].detector, DETECTOR_NAME)
        self.assertEqual(positive[0].function, "relayBatch")
        self.assertIn("domain skip and dispatch failure continue after consume", positive[0].message)

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
