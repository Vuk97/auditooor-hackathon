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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "bridge_proof_route_consume_fire24.py"
POSITIVE = REPO / "detectors" / "test_fixtures" / "positive" / "bridge_proof_route_consume_fire24.sol"
NEGATIVE = REPO / "detectors" / "test_fixtures" / "negative" / "bridge_proof_route_consume_fire24.sol"
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "bridge-proof-route-consume-fire24"


def _load_detector():
    module_name = "bridge_proof_route_consume_fire24"
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


class BridgeProofRouteConsumeFire24Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)
        detector_text = _read(DETECTOR_PATH)
        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn("candidate evidence only", detector_text)
        self.assertIn("weak consume key", detector_text)
        self.assertIn("_weak_route_setters", detector_text)

    def test_fixture_pair_contains_semantic_contrast(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("function setBridgeRoute(", positive)
        self.assertNotIn("onlyOwner", positive)
        self.assertIn("require(msg.value >= executionFee", positive)
        self.assertNotIn("MIN_EXECUTION_FEE", positive)
        self.assertIn("keccak256(abi.encode(messageId))", positive)
        self.assertIn("processedMessages[consumedKey] = true;", positive)
        self.assertIn("route.dispatcher.call{value: executionFee}(payload)", positive)
        self.assertIn("emit MessageDispatchFailed(messageId);", positive)
        self.assertIn("return;", positive)

        self.assertIn("external onlyOwner", negative)
        self.assertIn("MIN_EXECUTION_FEE", negative)
        self.assertIn("revert FeeTooLow();", negative)
        self.assertIn("BRIDGE_DOMAIN", negative)
        self.assertIn("uint32(block.chainid)", negative)
        self.assertIn("address(this)", negative)
        self.assertIn("sourceDomain", negative)
        self.assertIn("destinationDomain", negative)
        self.assertIn("routeId", negative)
        self.assertIn("route.verifier", negative)
        self.assertIn("revert DispatchFailed();", negative)

        self.assertLess(
            positive.index("processedMessages[consumedKey] = true;"),
            positive.index("route.dispatcher.call{value: executionFee}(payload)"),
        )
        self.assertLess(
            negative.index("processedMessages[consumedKey] = true;"),
            negative.index("route.dispatcher.call{value: executionFee}(payload)"),
        )

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()
        positive = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(positive), 1)
        self.assertEqual(negative, [])
        self.assertEqual(positive[0].detector, DETECTOR_NAME)
        self.assertEqual(positive[0].function, "consumeBridgeMessage")
        self.assertIn("permissionless route mutation", positive[0].message)
        self.assertIn("fee floor bypass", positive[0].message)
        self.assertIn("non-reverting dispatch failure", positive[0].message)

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
