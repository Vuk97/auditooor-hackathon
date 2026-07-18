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
    REPO / "detectors" / "wave17" / "initializer_namespace_slot_collision_fire18.py"
)
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "initializer_namespace_slot_collision_fire18.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "initializer_namespace_slot_collision_fire18.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "initializer-namespace-slot-collision-fire18"


def _load_detector():
    module_name = "initializer_namespace_slot_collision_fire18"
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


class InitializerNamespaceSlotCollisionFire18Test(unittest.TestCase):
    def test_detector_metadata_and_fixture_shape(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        detector_text = _read(DETECTOR_PATH)
        positive_text = _read(POSITIVE)
        negative_text = _read(NEGATIVE)

        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn("_NAMESPACE_LITERAL_RE", detector_text)
        self.assertIn("_REMOVED_FIELD_COLLISION_RE", detector_text)
        self.assertIn("_DOMAIN_OR_AA_GUARD_RE", detector_text)
        self.assertIn("_FEE_CAP_RE", detector_text)

        self.assertIn("function initializeAccount(", positive_text)
        self.assertIn('keccak256("fire18.account.storage")', positive_text)
        self.assertIn("legacy mapping removed", positive_text)
        self.assertIn("s.remoteAccounts[sourceChainId][remoteChainId][localAccount] = remoteAccount;", positive_text)
        self.assertIn("s.protocolFeeBps = initialFeeBps;", positive_text)
        self.assertNotIn("SameChain", positive_text)
        self.assertNotIn("MAX_FEE_BPS", positive_text)

        self.assertIn("external onlyFactory initializer", negative_text)
        self.assertIn("if (sourceChainId == remoteChainId) revert SameChain();", negative_text)
        self.assertIn("if (localAccount == remoteAccount) revert SameAccount();", negative_text)
        self.assertIn("require(namespace == ACCOUNT_STORAGE_LOCATION", negative_text)
        self.assertIn("require(initialFeeBps <= MAX_FEE_BPS", negative_text)
        self.assertIn("uint256[48] __gap;", negative_text)

    def test_positive_fixture_fires_and_negative_fixture_stays_quiet(self) -> None:
        detector = _load_detector()

        positive_findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertGreaterEqual(len(positive_findings), 3)
        self.assertEqual(negative_findings, [])
        self.assertEqual({finding.detector for finding in positive_findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in positive_findings}, {"High"})
        self.assertIn("initializeAccount", {finding.function for finding in positive_findings})
        messages = "\n".join(finding.message for finding in positive_findings)
        self.assertIn("Duplicate ERC-7201 namespace or storage-slot literal", messages)
        self.assertIn("mapping before adding a new field without a reserved gap", messages)
        self.assertIn("account-abstraction or route state", messages)

    def test_regex_runner_reports_positive_only(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        with tempfile.TemporaryDirectory(prefix="fire18_initializer_") as tmp:
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

            self.assertGreaterEqual(positive_data["per_detector_counts"][DETECTOR_NAME], 3)
            self.assertEqual(negative_data["per_detector_counts"][DETECTOR_NAME], 0)
            self.assertEqual({Path(row["file"]).name for row in positive_data["findings"]}, {POSITIVE.name})
            self.assertEqual(negative_data["findings"], [])


if __name__ == "__main__":
    unittest.main()
