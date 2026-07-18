from __future__ import annotations

import importlib.util
import json
import os
import py_compile
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
DETECTOR_PATH = (
    REPO / "detectors" / "wave17" / "initializer_cross_chain_account_symmetry_fire27.py"
)
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "initializer_cross_chain_account_symmetry_fire27.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "initializer_cross_chain_account_symmetry_fire27.sol"
)
AA_SYMMETRY = REPO / "patterns" / "fixtures" / "cross-chain-aa-address-symmetry_vuln.sol"
PENDLE_ARRAY = REPO / "patterns" / "fixtures" / "fx-pendle-uninitialized-return-array_vuln.sol"
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "initializer-cross-chain-account-symmetry-fire27"


def _load_detector():
    module_name = "initializer_cross_chain_account_symmetry_fire27"
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


class InitializerCrossChainAccountSymmetryFire27Test(unittest.TestCase):
    def test_detector_and_fixture_sources_are_aligned(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR_PATH)
        positive_text = _read(POSITIVE)
        negative_text = _read(NEGATIVE)

        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn("cross-chain-aa-address-symmetry.yaml", detector_text)
        self.assertIn("erc7201-namespace-struct-field-removal-slot-collision.yaml", detector_text)
        self.assertIn("fx-pendle-uninitialized-return-array.yaml", detector_text)
        self.assertIn("_DOMAIN_BINDING_RE", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)

        self.assertIn("function initializeAccount(", positive_text)
        self.assertIn("function deployProxyAccount(", positive_text)
        self.assertIn("bytes32 accountSalt = keccak256(abi.encode(owner, userSalt));", positive_text)
        self.assertIn("bytes32 proxySalt = keccak256(abi.encodePacked(owner, userSalt));", positive_text)
        self.assertIn("Create2.computeAddress(accountSalt", positive_text)
        self.assertIn("new ERC1967Proxy{salt: proxySalt}", positive_text)
        self.assertNotIn("SALT_DOMAIN,\n                block.chainid", positive_text)

        self.assertIn("external onlyFactory", negative_text)
        self.assertIn("SALT_DOMAIN", negative_text)
        self.assertIn("block.chainid", negative_text)
        self.assertIn("destinationChainId", negative_text)
        self.assertIn("address(this)", negative_text)
        self.assertIn("ENTRY_POINT", negative_text)
        self.assertIn("accountImplementation", negative_text)
        self.assertIn("function initialize(address owner) external", negative_text)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        positive_findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(positive_findings), 2)
        self.assertEqual(negative_findings, [])
        self.assertEqual({finding.detector for finding in positive_findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in positive_findings}, {"High"})
        self.assertEqual(
            {finding.function for finding in positive_findings},
            {"initializeAccount", "deployProxyAccount"},
        )
        messages = "\n".join(finding.message for finding in positive_findings)
        self.assertIn("without chain id, entry point, factory, salt-domain, or implementation binding", messages)
        self.assertIn("cross-chain account or authority symmetry", messages)

    def test_boundary_refs_do_not_trigger_this_narrow_initializer_detector(self) -> None:
        detector = _load_detector()

        aa_symmetry = detector.scan(_read(AA_SYMMETRY), str(AA_SYMMETRY))
        pendle_array = detector.scan(_read(PENDLE_ARRAY), str(PENDLE_ARRAY))

        self.assertEqual(aa_symmetry, [])
        self.assertEqual(pendle_array, [])

    def test_regex_runner_reports_positive_only(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        with tempfile.TemporaryDirectory(prefix="fire27_initializer_symmetry_") as tmp:
            positive_manifest = Path(tmp) / "positive.json"
            negative_manifest = Path(tmp) / "negative.json"

            positive_proc = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    str(POSITIVE),
                    "--workspace",
                    tmp,
                    "--output",
                    str(positive_manifest),
                    "--detector",
                    DETECTOR_NAME,
                    "--json-only",
                ],
                cwd=REPO,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=30,
            )
            self.assertEqual(positive_proc.returncode, 0, positive_proc.stdout)

            negative_proc = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    str(NEGATIVE),
                    "--workspace",
                    tmp,
                    "--output",
                    str(negative_manifest),
                    "--detector",
                    DETECTOR_NAME,
                    "--json-only",
                ],
                cwd=REPO,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=30,
            )
            self.assertEqual(negative_proc.returncode, 0, negative_proc.stdout)

            positive_data = json.loads(positive_manifest.read_text(encoding="utf-8"))
            negative_data = json.loads(negative_manifest.read_text(encoding="utf-8"))

            self.assertEqual(positive_data["per_detector_counts"][DETECTOR_NAME], 2)
            self.assertEqual(negative_data["per_detector_counts"][DETECTOR_NAME], 0)
            self.assertEqual({Path(row["file"]).name for row in positive_data["findings"]}, {POSITIVE.name})
            self.assertEqual(negative_data["findings"], [])


if __name__ == "__main__":
    unittest.main()
