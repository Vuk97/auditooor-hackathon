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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "initializer_owner_front_run_fire33.py"
POSITIVE = REPO / "detectors" / "test_fixtures" / "positive" / "initializer_owner_front_run_fire33.sol"
NEGATIVE = REPO / "detectors" / "test_fixtures" / "negative" / "initializer_owner_front_run_fire33.sol"
CLONE_VULN = REPO / "detectors" / "test_fixtures" / "clone_fee_recipient_init_permissionless_frontrun_vulnerable.sol"
CLONE_CLEAN = REPO / "detectors" / "test_fixtures" / "clone_fee_recipient_init_permissionless_frontrun_clean.sol"
PENDLE_VULN = REPO / "patterns" / "fixtures" / "fx-pendle-initializer-owner-order_vuln.sol"
PENDLE_CLEAN = REPO / "patterns" / "fixtures" / "fx-pendle-initializer-owner-order_clean.sol"
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "initializer-owner-front-run-fire33"


def _load_detector():
    module_name = "initializer_owner_front_run_fire33"
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


class InitializerOwnerFrontRunFire33Test(unittest.TestCase):
    def test_detector_and_fixture_sources_are_aligned(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR_PATH)
        positive_text = _read(POSITIVE)
        negative_text = _read(NEGATIVE)

        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn("initializer-front-run", detector_text)
        self.assertIn("r94-loop-init-race-admin-takeover.yaml", detector_text)
        self.assertIn("clone-fee-recipient-init-permissionless-frontrun.yaml", detector_text)
        self.assertIn("fx-pendle-initializer-owner-order.yaml", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)
        self.assertIn("_disableInitializers", detector_text)
        self.assertIn("_OWNABLE_INIT_DIRECT_RE", detector_text)

        self.assertIn("function initialize(address newOwner, address newRouter", positive_text)
        self.assertIn("owner = newOwner;", positive_text)
        self.assertIn("function initRecipient(address newDispatcher", positive_text)
        self.assertIn("dispatcher = newDispatcher;", positive_text)
        self.assertIn("function setFeeRecipient(address newFeeRecipient) external", positive_text)
        self.assertIn("__BoringOwnableV2_init(newOwner);", positive_text)
        self.assertIn("_grantRole(DEFAULT_ADMIN_ROLE, admin);", positive_text)

        self.assertIn("external onlyFactory initializer", negative_text)
        self.assertIn("stakingContract = msg.sender;", negative_text)
        self.assertIn("_disableInitializers();", negative_text)
        self.assertIn("__BoringOwnableV2_init(msg.sender);", negative_text)
        self.assertIn("transferOwnership(newOwner, true, false);", negative_text)
        self.assertIn("function setRouter(address newRouter) external onlyOwner", negative_text)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        positive_findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(positive_findings), 7)
        self.assertEqual(negative_findings, [])
        self.assertEqual({finding.detector for finding in positive_findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in positive_findings}, {"High"})
        self.assertEqual(
            {finding.function for finding in positive_findings},
            {"initialize", "initRecipient", "setOwner", "setFeeRecipient", "setRouter", "setup"},
        )
        messages = "\n".join(finding.message for finding in positive_findings)
        self.assertIn("first-call owner or role binding", messages)
        self.assertIn("first-call router, fee recipient, dispatcher, or clone destination binding", messages)
        self.assertIn("unguarded setup setter", messages)
        self.assertIn("owner passed directly to Ownable init instead of msg.sender setup handoff", messages)
        self.assertIn("implementation initializer remains callable", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def test_source_ref_replays_cover_clone_and_owner_order_boundaries(self) -> None:
        detector = _load_detector()

        clone_vuln = detector.scan(_read(CLONE_VULN), str(CLONE_VULN))
        clone_clean = detector.scan(_read(CLONE_CLEAN), str(CLONE_CLEAN))
        pendle_vuln = detector.scan(_read(PENDLE_VULN), str(PENDLE_VULN))
        pendle_clean = detector.scan(_read(PENDLE_CLEAN), str(PENDLE_CLEAN))

        self.assertEqual({finding.function for finding in clone_vuln}, {"init"})
        self.assertEqual(clone_clean, [])
        self.assertEqual({finding.function for finding in pendle_vuln}, {"initialize"})
        self.assertEqual(pendle_clean, [])

    def test_regex_runner_reports_positive_only(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        with tempfile.TemporaryDirectory(prefix="fire33_initializer_owner_") as tmp:
            positive_manifest = Path(tmp) / "positive.json"
            negative_manifest = Path(tmp) / "negative.json"

            for fixture, manifest in ((POSITIVE, positive_manifest), (NEGATIVE, negative_manifest)):
                proc = subprocess.run(
                    [
                        sys.executable,
                        str(RUNNER),
                        str(fixture),
                        "--workspace",
                        tmp,
                        "--output",
                        str(manifest),
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
                self.assertEqual(proc.returncode, 0, proc.stdout)

            positive_data = json.loads(positive_manifest.read_text(encoding="utf-8"))
            negative_data = json.loads(negative_manifest.read_text(encoding="utf-8"))

            self.assertEqual(positive_data["per_detector_counts"][DETECTOR_NAME], 7)
            self.assertEqual(negative_data["per_detector_counts"][DETECTOR_NAME], 0)
            self.assertEqual(
                {Path(row["file"]).name for row in positive_data["findings"]},
                {POSITIVE.name},
            )
            self.assertEqual(negative_data["findings"], [])


if __name__ == "__main__":
    unittest.main()
