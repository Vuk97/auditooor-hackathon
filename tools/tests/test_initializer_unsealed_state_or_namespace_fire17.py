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
    REPO / "detectors" / "wave17" / "initializer_unsealed_state_or_namespace_fire17.py"
)
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "initializer_unsealed_state_or_namespace_fire17.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "initializer_unsealed_state_or_namespace_fire17.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "initializer-unsealed-state-or-namespace-fire17"


def _load_detector():
    module_name = "initializer_unsealed_state_or_namespace_fire17"
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


class InitializerUnsealedStateOrNamespaceFire17Test(unittest.TestCase):
    def test_detector_metadata_and_fixture_shape(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        detector_text = _read(DETECTOR_PATH)
        positive_text = _read(POSITIVE)
        negative_text = _read(NEGATIVE)

        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn("does not treat an", detector_text)
        self.assertIn("initializer", detector_text)
        self.assertIn("_AUTH_BINDING_RE", detector_text)
        self.assertIn("_VERSION_OR_ORDER_RE", detector_text)
        self.assertIn("_MONOTONIC_INDEX_RE", detector_text)

        self.assertIn("function initializeGateway(", positive_text)
        self.assertIn("external\n        initializer", positive_text)
        self.assertIn("s.owner = configuredOwner;", positive_text)
        self.assertIn("reserveData[asset].liquidityIndex = initialLiquidityIndex;", positive_text)
        self.assertIn("remoteAccounts[accountId][remoteChainId] = remoteAccount;", positive_text)
        self.assertNotIn("onlyFactory", positive_text)
        self.assertNotIn("onlyPoolConfigurator", positive_text)

        self.assertIn("external\n        onlyFactory\n        initializer", negative_text)
        self.assertIn("require(configuredNamespace == EXPECTED_NAMESPACE", negative_text)
        self.assertIn("require(reserve.initializedVersion < 2", negative_text)
        self.assertIn("require(initialLiquidityIndex >= oldIndex", negative_text)
        self.assertIn("require(accountOwner[accountId] == msg.sender", negative_text)
        self.assertIn("constructor(address expectedFactory)", negative_text)

    def test_positive_fixture_fires_and_negative_fixture_stays_quiet(self) -> None:
        detector = _load_detector()

        positive_findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(positive_findings), 3)
        self.assertEqual(negative_findings, [])
        self.assertEqual({finding.detector for finding in positive_findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in positive_findings}, {"High"})
        self.assertEqual(
            {finding.function for finding in positive_findings},
            {"initializeGateway", "initReserve", "initializeAccount"},
        )
        messages = "\n".join(finding.message for finding in positive_findings)
        self.assertIn("durable initializer, namespace, index, route, or cross-chain account state", messages)
        self.assertIn("caller binding or versioned order protection", messages)

    def test_regex_runner_reports_positive_only(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        with tempfile.TemporaryDirectory(prefix="fire17_initializer_") as tmp:
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

            self.assertEqual(positive_data["per_detector_counts"][DETECTOR_NAME], 3)
            self.assertEqual(negative_data["per_detector_counts"][DETECTOR_NAME], 0)
            self.assertEqual({Path(row["file"]).name for row in positive_data["findings"]}, {POSITIVE.name})
            self.assertEqual(negative_data["findings"], [])


if __name__ == "__main__":
    unittest.main()
