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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "emergency_asset_scope_bypass_fire31.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "emergency_asset_scope_bypass_fire31.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "emergency_asset_scope_bypass_fire31.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "emergency-asset-scope-bypass-fire31"


def _load_detector():
    module_name = "emergency_asset_scope_bypass_fire31"
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


class EmergencyAssetScopeBypassFire31Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_detector_cites_source_backed_records_and_honesty_marker(self) -> None:
        text = _read(DETECTOR_PATH)
        self.assertIn("post_priorities_all.md", text)
        self.assertIn("emergency_unpause_bypass_fire29.py", text)
        self.assertIn("reentrancy-during-pause", text)
        self.assertIn("collateral-can-be-enabled-despite-pause-freeze-or-invalid-pricing", text)
        self.assertIn("destination-adapter-does-not-pause-on-source-side-pause-event", text)
        self.assertIn("NOT_SUBMIT_READY", text)
        self.assertIn("PROMOTION_ALLOWED = False", text)

    def test_positive_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        clean_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(clean_findings, [])
        self.assertEqual(len(findings), 3)
        self.assertEqual({finding.detector for finding in findings}, {DETECTOR_NAME})
        self.assertEqual(
            {finding.function for finding in findings},
            {
                "deposit",
                "enableCollateral",
                "releaseFromBridge",
            },
        )

        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("asset-or-reserve-value-path-global-only", messages)
        self.assertIn("collateral-or-asset-enable-global-only", messages)
        self.assertIn("bridge-or-adapter-global-pause-only", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def test_fixture_pair_locks_false_positive_boundaries(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("function deposit(address asset, uint256 amount) external whenNotPaused", positive)
        self.assertIn("collateralEnabled[msg.sender][reserve] = true;", positive)
        self.assertIn("bridgeCredits[adapter][asset] -= amount;", positive)
        self.assertNotIn("whenAssetLive(asset)", positive)
        self.assertNotIn("_validateReserveActive(reserve);", positive)

        self.assertIn("function deposit(address asset, uint256 amount) external whenNotPaused whenAssetLive(asset)", negative)
        self.assertIn("_validateReserveActive(reserve);", negative)
        self.assertIn("whenAdapterLive(adapter)", negative)
        self.assertIn("require(!assetPaused[asset]", negative)

    def test_global_pause_only_function_without_scoped_state_is_not_flagged(self) -> None:
        detector = _load_detector()
        source = """
        contract GlobalPauseOnlyFire31 {
            bool public paused;
            uint256 public totalDeposits;
            modifier whenNotPaused() {
                require(!paused, "paused");
                _;
            }
            function deposit(uint256 amount) external whenNotPaused {
                totalDeposits += amount;
            }
        }
        """
        self.assertEqual(detector.scan(source, "GlobalPauseOnlyFire31.sol"), [])

    def test_scoped_admin_state_setter_is_not_the_value_path(self) -> None:
        detector = _load_detector()
        source = """
        contract ScopedPauseSetterFire31 {
            bool public paused;
            mapping(address => bool) public assetPaused;
            modifier whenNotPaused() {
                require(!paused, "paused");
                _;
            }
            function setAssetPaused(address asset, bool paused_) external whenNotPaused {
                assetPaused[asset] = paused_;
            }
        }
        """
        self.assertEqual(detector.scan(source, "ScopedPauseSetterFire31.sol"), [])

    def test_regex_runner_discovers_detector_for_owned_fixture_pair(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        for fixture, expected_hits in ((POSITIVE, 3), (NEGATIVE, 0)):
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
                match = re.search(r"total hits:\s*(\d+)", proc.stdout)
                self.assertIsNotNone(match, proc.stdout)
                self.assertEqual(int(match.group(1)), expected_hits, proc.stdout)


if __name__ == "__main__":
    unittest.main()
