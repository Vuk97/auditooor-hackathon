"""Focused regression and smoke test for the bounded G1 shared-helper slice."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
RUN_CUSTOM = REPO / "detectors" / "run_custom.py"
DETECTOR = "shared-helper-unguarded-entrypoint-bypass"
FIXTURE_DIR = REPO / "detectors" / "_fixtures" / "shared_helper_unguarded_entrypoint_bypass"
FIXTURE_VULN = FIXTURE_DIR / "WorkerRegistry_vulnerable.sol"
FIXTURE_CLEAN = FIXTURE_DIR / "WorkerRegistry_clean.sol"
FIXTURE_PAIRS = [
    (FIXTURE_VULN, FIXTURE_CLEAN),
    (
        FIXTURE_DIR / "CollateralExitModifier_vulnerable.sol",
        FIXTURE_DIR / "CollateralExitModifier_clean.sol",
    ),
    (
        FIXTURE_DIR / "EscrowClaimInternalGuard_vulnerable.sol",
        FIXTURE_DIR / "EscrowClaimInternalGuard_clean.sol",
    ),
]


def _python_with_slither() -> str | None:
    candidates = [
        os.environ.get("SLITHER_PYTHON"),
        sys.executable,
        "/opt/homebrew/opt/python@3.13/bin/python3.13",
        "/opt/homebrew/bin/python3.13",
    ]
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        try:
            probe = subprocess.run(
                [
                    candidate,
                    "-c",
                    "import slither; import slither.detectors.abstract_detector",
                ],
                cwd=REPO,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if probe.returncode == 0:
            return candidate
    return None


class SharedHelperFixtureShapeTest(unittest.TestCase):
    def test_fixture_pairs_are_present(self) -> None:
        for vuln_fixture, clean_fixture in FIXTURE_PAIRS:
            self.assertTrue(vuln_fixture.is_file(), f"missing fixture: {vuln_fixture}")
            self.assertTrue(clean_fixture.is_file(), f"missing fixture: {clean_fixture}")

    def test_vulnerable_fixture_has_direct_bypass(self) -> None:
        source = FIXTURE_VULN.read_text(encoding="utf-8")
        self.assertIn("function withdrawAfterDeregister", source)
        self.assertIn("function emergencyWithdraw", source)
        self.assertIn("_assertWithdrawalReady(msg.sender);", source)
        self.assertIn("function emergencyWithdraw(uint256 amount) external {\n        _withdrawStake(msg.sender, amount);", source)

    def test_clean_fixture_reuses_guard_helper(self) -> None:
        source = FIXTURE_CLEAN.read_text(encoding="utf-8")
        self.assertEqual(source.count("_assertWithdrawalReady(msg.sender);"), 2)

    def test_modifier_pair_covers_guarded_admin_emergency_path(self) -> None:
        vuln_source = (FIXTURE_DIR / "CollateralExitModifier_vulnerable.sol").read_text(encoding="utf-8")
        clean_source = (FIXTURE_DIR / "CollateralExitModifier_clean.sol").read_text(encoding="utf-8")

        self.assertIn(
            "function withdrawAfterExit(uint256 amount) external onlyCooldownComplete(msg.sender)",
            vuln_source,
        )
        self.assertIn(
            "function emergencyRelease(uint256 amount) external {\n        _releaseCollateral(msg.sender, amount);",
            vuln_source,
        )
        self.assertIn(
            "function emergencyRelease(address account, uint256 amount) external onlyAdmin whenPaused",
            clean_source,
        )

    def test_helper_guard_pair_covers_guard_inside_shared_helper(self) -> None:
        vuln_source = (FIXTURE_DIR / "EscrowClaimInternalGuard_vulnerable.sol").read_text(encoding="utf-8")
        clean_source = (FIXTURE_DIR / "EscrowClaimInternalGuard_clean.sol").read_text(encoding="utf-8")

        self.assertIn(
            "function claimAfterDelay(uint256 amount) external {\n        _requireClaimReady(msg.sender);",
            vuln_source,
        )
        self.assertIn(
            "function fastClaim(uint256 amount) external {\n        _claimEscrow(msg.sender, amount);",
            vuln_source,
        )
        self.assertIn(
            "function _claimEscrow(address account, uint256 amount) internal {\n        _requireClaimReady(account);",
            clean_source,
        )


class SharedHelperUnguardedEntrypointBypassSmokeTest(unittest.TestCase):
    def test_vuln_fixture_hits_and_clean_fixture_does_not(self) -> None:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by an available Python interpreter")

        for vuln_fixture, clean_fixture in FIXTURE_PAIRS:
            with self.subTest(vulnerable=vuln_fixture.name, clean=clean_fixture.name):
                with tempfile.TemporaryDirectory(prefix="shared_helper_bypass_") as tmp:
                    scratch = Path(tmp)
                    for fixture in (vuln_fixture, clean_fixture):
                        (scratch / fixture.name).write_text(
                            fixture.read_text(encoding="utf-8"),
                            encoding="utf-8",
                        )
                    (scratch / "foundry.toml").write_text(
                        '[profile.default]\nsrc = "."\nout = "out"\n',
                        encoding="utf-8",
                    )
                    regression = scratch / "regression.tsv"
                    regression.write_text(
                        "\n".join(
                            [
                                f"vuln\t{DETECTOR}\t{vuln_fixture.name}\t{DETECTOR}",
                                f"clean\t{DETECTOR}\t{clean_fixture.name}\t{DETECTOR} (clean)",
                                "",
                            ]
                        ),
                        encoding="utf-8",
                    )

                    env = os.environ.copy()
                    env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
                    proc = subprocess.run(
                        [
                            slither_python,
                            str(RUN_CUSTOM),
                            "--batch",
                            str(scratch),
                            str(regression),
                            "--tier=ALL",
                        ],
                        cwd=REPO,
                        env=env,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        timeout=120,
                    )

                self.assertEqual(proc.returncode, 0, proc.stdout)
                self.assertIn("Batch regression: 2/2 passed, 0 failed", proc.stdout)


if __name__ == "__main__":
    unittest.main()
