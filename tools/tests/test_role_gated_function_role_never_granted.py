#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import py_compile
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
INVENTORY_SMOKE = ROOT / "tools" / "inventory-smoke-test.py"
PATTERN = "role-gated-function-role-never-granted"
DETECTOR = ROOT / "detectors" / "wave17" / "role_gated_function_role_never_granted.py"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "role_gated_function_role_never_granted"
POSITIVE = FIXTURE_DIR / "positive.sol"
WRONG_ROLE = FIXTURE_DIR / "positive_wrong_role.sol"
LATE_GRANT = FIXTURE_DIR / "positive_later_admin_grant.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
CLEAN_INIT_HELPER = FIXTURE_DIR / "clean_init_helper.sol"
SMOKE = FIXTURE_DIR / "smoke.json"


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
                [candidate, "-c", "import slither; import slither.detectors.abstract_detector"],
                cwd=ROOT,
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


class RoleGatedFunctionRoleNeverGrantedTest(unittest.TestCase):
    def _hits(self, fixture: Path) -> int:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [
                slither_python,
                str(RUNNER),
                "--tier=ALL",
                str(fixture),
                PATTERN,
            ],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertNotIn("No custom detectors found", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_detector_reference_and_fixture_metadata(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        reference_text = REFERENCE.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        wrong_role_text = WRONG_ROLE.read_text(encoding="utf-8")
        late_grant_text = LATE_GRANT.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")
        clean_init_helper_text = CLEAN_INIT_HELPER.read_text(encoding="utf-8")
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))

        self.assertIn('ARGUMENT = "role-gated-function-role-never-granted"', detector_text)
        self.assertIn("pattern: role-gated-function-role-never-granted", reference_text)
        self.assertIn("contract.has_state_var_matching", reference_text)
        self.assertIn("contract.source_matches_regex", reference_text)
        self.assertIn("function.body_contains_regex", reference_text)
        self.assertIn("function.name_matches", reference_text)
        self.assertIn("function.not_in_skip_list", reference_text)
        self.assertIn("function.not_leaf_helper", reference_text)
        self.assertIn("function.not_source_matches_regex", reference_text)
        self.assertNotIn("contract.source_not_contains_regex", reference_text)

        self.assertIn("function withdraw(address recipient) external", positive_text)
        self.assertIn("_checkRole(WRAPPER_ROLE);", positive_text)
        self.assertNotIn("_grantRole(", positive_text)

        self.assertIn("_grantRole(DEFAULT_ADMIN_ROLE, msg.sender);", wrong_role_text)
        self.assertIn("_checkRole(WRAPPER_ROLE);", wrong_role_text)

        self.assertIn("function configureWrapper(address wrapper) external", late_grant_text)
        self.assertIn("_grantRole(WRAPPER_ROLE, wrapper);", late_grant_text)
        self.assertIn("_grantRole(DEFAULT_ADMIN_ROLE, msg.sender);", late_grant_text)
        self.assertIn("_checkRole(WRAPPER_ROLE);", late_grant_text)

        self.assertIn("constructor()", clean_text)
        self.assertIn("_grantRole(WRAPPER_ROLE, msg.sender);", clean_text)
        self.assertIn("_checkRole(WRAPPER_ROLE);", clean_text)

        self.assertIn("function initialize(address wrapper_) external", clean_init_helper_text)
        self.assertIn("_grantWrapperRole(wrapper_);", clean_init_helper_text)
        self.assertIn("_grantRole(WRAPPER_ROLE, account);", clean_init_helper_text)
        self.assertIn("_checkRole(WRAPPER_ROLE);", clean_init_helper_text)

        self.assertEqual(payload["schema"], "auditooor.canonical_detector_fixture_smoke.v1")
        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["detector_slug"], "role_gated_function_role_never_granted")
        self.assertEqual(payload["fixture_id"], "role_gated_function_role_never_granted")
        self.assertEqual(payload["detector_path"], "detectors/wave17/role_gated_function_role_never_granted.py")
        self.assertEqual(payload["coverage_claim"], "detector_fixture_smoke_only")
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertGreaterEqual(self._hits(POSITIVE), 1)
        self.assertGreaterEqual(self._hits(WRONG_ROLE), 1)
        self.assertGreaterEqual(self._hits(LATE_GRANT), 1)
        self.assertEqual(self._hits(CLEAN), 0)
        self.assertEqual(self._hits(CLEAN_INIT_HELPER), 0)

    def test_inventory_smoke_exact_detector_reports_one_pass(self) -> None:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        env["SLITHER_PYTHON"] = slither_python

        with tempfile.TemporaryDirectory(prefix="inventory-smoke-role-gated-") as tmp:
            proc = subprocess.run(
                [
                    slither_python,
                    str(INVENTORY_SMOKE),
                    "--output-dir",
                    tmp,
                    "--detector",
                    PATTERN,
                    "--workers",
                    "1",
                ],
                cwd=ROOT,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=180,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout)
            summary = json.loads((Path(tmp) / "inventory_smoke_summary.json").read_text(encoding="utf-8"))

        self.assertEqual(summary["total_detectors_scanned"], 1)
        self.assertEqual(summary["by_status"].get("smoke_pass"), 1)
        self.assertEqual(len(summary["results"]), 1)
        self.assertEqual(summary["results"][0]["argument"], PATTERN)
        self.assertEqual(summary["results"][0]["status"], "smoke_pass")
        self.assertGreaterEqual(summary["results"][0]["vuln_hits"], 1)
        self.assertEqual(summary["results"][0]["clean_hits"], 0)


if __name__ == "__main__":
    unittest.main()
