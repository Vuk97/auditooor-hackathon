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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "bridge_proof_beefyclient_mmr_root_fire26.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "bridge_proof_beefyclient_mmr_root_fire26.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "bridge_proof_beefyclient_mmr_root_fire26.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "bridge-proof-beefyclient-mmr-root-fire26"
SNOWBRIDGE_BEEFY_PREFIX = (
    REPO
    / "reports"
    / "external_recall_snapshots"
    / "snowbridge_ba20bc65_parent"
    / "contracts"
    / "src"
    / "BeefyClient.sol"
)


def _load_detector():
    module_name = "bridge_proof_beefyclient_mmr_root_fire26"
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


class BridgeProofBeefyClientMmrRootFire26Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR_PATH)
        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn('SUBMISSION_POSTURE = "NOT_SUBMIT_READY"', detector_text)
        self.assertIn("detector_fixture_smoke_only", detector_text)
        self.assertIn("_has_domain_bound_root_before_sink", detector_text)
        self.assertIn("source chain, BEEFY client", detector_text)

    def test_fixture_pair_contains_semantic_contrast(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("sourceChainId", positive)
        self.assertIn("beefyClientId", positive)
        self.assertIn("consensusDomain", positive)
        self.assertIn("destinationApplication", positive)
        self.assertIn("ensureProvidesMMRRoot(commitment)", positive)
        self.assertIn("verifyFiatShamirCommitment(commitmentHash", positive)
        self.assertIn("latestMMRRoot = newMMRRoot;", positive)
        self.assertNotIn("BEEFY_MMR_ROOT_DOMAIN", positive)

        self.assertIn("BEEFY_MMR_ROOT_DOMAIN", negative)
        self.assertIn("rootAcceptanceDigest = keccak256(", negative)
        self.assertIn("sourceChainId,\n                beefyClientId", negative)
        self.assertIn("consensusDomain,\n                destinationApplication", negative)
        self.assertIn("currentValidatorSet.root,\n                currentValidatorSet.id", negative)
        self.assertIn("commitmentHash,\n                newMMRRoot", negative)
        self.assertLess(
            negative.index("bytes32 rootAcceptanceDigest = keccak256("),
            negative.index("verifyFiatShamirCommitment(rootAcceptanceDigest"),
        )
        self.assertLess(
            negative.index("verifyFiatShamirCommitment(rootAcceptanceDigest"),
            negative.index("latestMMRRoot = newMMRRoot;"),
        )

    def test_snowbridge_prefix_source_evidence_is_real(self) -> None:
        source = _read(SNOWBRIDGE_BEEFY_PREFIX)

        self.assertIn("function submitFiatShamir", source)
        self.assertIn("bytes32 newMMRRoot = ensureProvidesMMRRoot(commitment)", source)
        self.assertIn("verifyFiatShamirCommitment(commitmentHash, bitfield, vset, proofs)", source)
        self.assertIn("latestMMRRoot = newMMRRoot", source)
        self.assertIn("createFiatShamirHash(commitmentHash, bitFieldHash, vsetRoot)", source)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()
        positive = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(positive), 1)
        self.assertEqual(negative, [])
        self.assertEqual(positive[0].detector, DETECTOR_NAME)
        self.assertEqual(positive[0].function, "submitFiatShamir")
        self.assertIn("consensus_domain", positive[0].message)
        self.assertIn("destination_app", positive[0].message)

    def test_snowbridge_prefix_source_fires_on_root_acceptance_sink(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read(SNOWBRIDGE_BEEFY_PREFIX), str(SNOWBRIDGE_BEEFY_PREFIX))

        functions = {finding.function for finding in findings}
        self.assertIn("submitFiatShamir", functions)
        self.assertGreaterEqual(len(findings), 1)
        for finding in findings:
            self.assertEqual(finding.detector, DETECTOR_NAME)
            self.assertIn("BEEFY/MMR root acceptance", finding.message)

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
