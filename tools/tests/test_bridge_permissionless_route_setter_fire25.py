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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "bridge_permissionless_route_setter_fire25.py"
POSITIVE = REPO / "detectors" / "test_fixtures" / "positive" / "bridge_permissionless_route_setter_fire25.sol"
NEGATIVE = REPO / "detectors" / "test_fixtures" / "negative" / "bridge_permissionless_route_setter_fire25.sol"
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "bridge-permissionless-route-setter-fire25"


def _load_detector():
    module_name = "bridge_permissionless_route_setter_fire25"
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


class BridgePermissionlessRouteSetterFire25Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR_PATH)
        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn("candidate evidence only", detector_text)
        self.assertIn("_weak_route_setters", detector_text)
        self.assertIn("_has_route_proof_or_dispatch_consumer", detector_text)

    def test_fixture_pair_contains_semantic_contrast(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("function setBridgeRoute(", positive)
        self.assertNotIn("onlyRouteAdmin", positive)
        self.assertIn("bridgeRoutes[sourceChainId][destinationChainId] = BridgeRoute", positive)
        self.assertIn("function consumeBridgeProof(", positive)
        self.assertIn("IBridgeRouteEndpoint(route.endpoint).settle(proofRoot, payload);", positive)
        self.assertIn("keccak256(abi.encode(proofRoot))", positive)

        self.assertIn("constructor(address initialAdmin", negative)
        self.assertIn("bridgeRoutes[1][2] = BridgeRoute", negative)
        self.assertIn("external onlyRouteAdmin", negative)
        self.assertIn("hasRole(ROUTE_ADMIN_ROLE, msg.sender)", negative)
        self.assertIn("sourceChainId != destinationChainId", negative)
        self.assertIn("route.receiver", negative)
        self.assertIn("route.endpoint", negative)
        self.assertIn("address(this)", negative)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()
        positive = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(positive), 1)
        self.assertEqual(negative, [])
        self.assertEqual(positive[0].detector, DETECTOR_NAME)
        self.assertEqual(positive[0].function, "setBridgeRoute")
        self.assertIn("Public bridge route setter", positive[0].message)
        self.assertIn("Candidate evidence only", positive[0].message)

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
