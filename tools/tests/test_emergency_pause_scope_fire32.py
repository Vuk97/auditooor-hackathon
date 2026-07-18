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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "emergency_pause_scope_fire32.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "emergency_pause_scope_fire32.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "emergency_pause_scope_fire32.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "emergency-pause-scope-fire32"


def _load_detector():
    module_name = "emergency_pause_scope_fire32"
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


class EmergencyPauseScopeFire32Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_detector_cites_source_backed_records_and_honesty_marker(self) -> None:
        text = _read(DETECTOR_PATH)
        self.assertIn("post_priorities_all.md", text)
        self.assertIn("emergency_asset_scope_bypass_fire31.py", text)
        self.assertIn("reentrancy-during-pause", text)
        self.assertIn("emergency-admin-can-unpause-reserves-breaking-pause-asymmetry", text)
        self.assertIn("NOT_SUBMIT_READY", text)
        self.assertIn("PROMOTION_ALLOWED = False", text)

    def test_positive_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        clean_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(clean_findings, [])
        self.assertEqual(len(findings), 4)
        self.assertEqual({finding.detector for finding in findings}, {DETECTOR_NAME})
        self.assertEqual(
            {finding.function for finding in findings},
            {
                "withdraw",
                "redeem",
                "claim",
                "settleRoute",
            },
        )

        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("exit-path-global-pause-only", messages)
        self.assertIn("exit-path-no-pause-scope", messages)
        self.assertIn("exit-path-wrong-scoped-pause-check", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def test_fixture_pair_locks_false_positive_boundaries(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("function withdraw(address asset, uint256 amount) external whenNotPaused", positive)
        self.assertIn("function redeem(address reserve, uint256 amount) external", positive)
        self.assertIn('require(!assetPaused[token], "asset paused");', positive)
        self.assertIn("routeEscrow[routeId] -= amount;", positive)
        self.assertNotIn("whenAssetLive(asset)", positive)
        self.assertNotIn("_requireReserveActive(reserve);", positive)
        self.assertNotIn("whenRouteOpen(routeId)", positive)

        self.assertIn("whenAssetLive(asset)", negative)
        self.assertIn("_requireReserveActive(reserve);", negative)
        self.assertIn('require(!marketPaused[market], "market paused");', negative)
        self.assertIn("whenRouteOpen(routeId)", negative)
        self.assertIn("function emergencyWithdraw(address asset, uint256 amount) external whenPaused", negative)

    def test_global_guarded_unscoped_withdraw_is_not_flagged(self) -> None:
        detector = _load_detector()
        source = """
        contract GlobalOnlyWithdrawFire32 {
            bool public paused;
            mapping(address => uint256) public shares;
            address public asset;
            modifier whenNotPaused() {
                require(!paused, "paused");
                _;
            }
            function withdraw(uint256 amount) external whenNotPaused {
                shares[msg.sender] -= amount;
                Fire32Token(asset).safeTransfer(msg.sender, amount);
            }
        }
        """
        self.assertEqual(detector.scan(source, "GlobalOnlyWithdrawFire32.sol"), [])

    def test_admin_pause_setter_and_view_are_not_flagged(self) -> None:
        detector = _load_detector()
        source = """
        contract PauseSetterFire32 {
            bool public protocolPaused;
            mapping(address => bool) public assetPaused;
            mapping(address => uint256) public balances;
            function setAssetPaused(address asset, bool paused_) external {
                assetPaused[asset] = paused_;
            }
            function claimable(address asset, address user) external view returns (uint256) {
                return balances[user];
            }
        }
        """
        self.assertEqual(detector.scan(source, "PauseSetterFire32.sol"), [])

    def test_regex_runner_discovers_detector_for_owned_fixture_pair(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        for fixture, expected_hits in ((POSITIVE, 4), (NEGATIVE, 0)):
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
