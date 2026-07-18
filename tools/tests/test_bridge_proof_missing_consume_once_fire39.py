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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "bridge_proof_missing_consume_once_fire39.py"
POSITIVE = REPO / "detectors" / "test_fixtures" / "positive" / "bridge_proof_missing_consume_once_fire39.sol"
NEGATIVE = REPO / "detectors" / "test_fixtures" / "negative" / "bridge_proof_missing_consume_once_fire39.sol"
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "bridge-proof-missing-consume-once-fire39"


def _load_detector():
    module_name = "bridge_proof_missing_consume_once_fire39"
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


class BridgeProofMissingConsumeOnceFire39Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)
        detector_text = _read(DETECTOR_PATH)
        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn("verification_tier: tier-3-synthetic-taxonomy-anchored", detector_text)
        self.assertIn("attack_class: signature-replay-cross-domain", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)
        self.assertIn("source-review candidates only", detector_text)

    def test_fixture_pair_contains_semantic_boundary(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("function finalizeBridgeWithdrawal(", positive)
        self.assertIn("Fire39MerkleProof.verify(proof, sourceRoot, leaf)", positive)
        self.assertIn("destinationChainId == uint32(block.chainid)", positive)
        self.assertIn("custodyToken.transfer(recipient, amount)", positive)
        self.assertNotIn("processedMessages", positive)
        self.assertNotIn("replayKey", positive)

        self.assertIn("mapping(bytes32 => bool) public processedMessages", negative)
        self.assertIn("bytes32 replayKey = keccak256(", negative)
        self.assertIn("sourceChainId, destinationChainId, address(this)", negative)
        self.assertIn("if (processedMessages[replayKey])", negative)
        self.assertIn("processedMessages[replayKey] = true;", negative)
        self.assertIn("Fire39MerkleProof.verify(proof, sourceRoot, leaf)", negative)
        self.assertIn("custodyToken.transfer(recipient, amount)", negative)

        self.assertLess(
            negative.index("if (processedMessages[replayKey])"),
            negative.index("custodyToken.transfer(recipient, amount)"),
        )
        self.assertLess(
            negative.index("processedMessages[replayKey] = true;"),
            negative.index("custodyToken.transfer(recipient, amount)"),
        )

    def test_positive_fires_and_domain_bound_consume_once_path_is_silent(self) -> None:
        detector = _load_detector()
        positive = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(positive), 1)
        self.assertEqual(negative, [])
        self.assertEqual(positive[0].detector, DETECTOR_NAME)
        self.assertEqual(positive[0].function, "finalizeBridgeWithdrawal")
        self.assertIn("no consume-once check or write before effect", positive[0].message)
        self.assertIn("replay protection is missing", positive[0].message)
        self.assertIn("Source-review candidates only", positive[0].message)

    def test_weak_consume_key_still_fires_when_superficial_guard_exists(self) -> None:
        detector = _load_detector()
        source = _read(NEGATIVE).replace(
            "abi.encode(sourceChainId, destinationChainId, address(this), nonce, recipient, amount, leaf)",
            "abi.encode(nonce, recipient, amount, leaf)",
        )
        findings = detector.scan(source, "weak-key.sol")

        self.assertEqual(len(findings), 1)
        self.assertIn("consume key is not bound", findings[0].message)

    def test_regex_runner_discovers_owned_detector(self) -> None:
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
