"""Unit tests for tools/impact-contract-validator.py.

Self-test using the hand-filled reference spec + a deliberately-broken
spec under tools/tests/fixtures/impact_contract_validator/.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = REPO_ROOT / "tools" / "impact-contract-validator.py"
FIXTURE_DIR = REPO_ROOT / "tools" / "tests" / "fixtures" / "impact_contract_validator"


def _load_module():
    name = "impact_contract_validator"
    spec = importlib.util.spec_from_file_location(name, TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


class ImpactContractValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_module()

    def test_reference_spec_passes_all_rules(self) -> None:
        path = FIXTURE_DIR / "reference_filled.md"
        results = self.mod.validate(path)
        statuses = {r.rule: r.status for r in results}
        self.assertEqual(len(results), 7, statuses)
        for rule, status in statuses.items():
            self.assertEqual(status, "PASS", f"{rule} expected PASS, got {status}")

    def test_broken_spec_fails_expected_rules(self) -> None:
        path = FIXTURE_DIR / "broken_filled.md"
        results = self.mod.validate(path)
        statuses = {r.rule: r.status for r in results}
        # Must FAIL on these rules:
        for rule in (
            "V1_no_todos",
            "V2_production_precondition",
            "V3_borrowed_assets",
            "V4_adversarial_consistency",
            "V5_severity_supports_listed_impact",
            "V7_title_schema",
        ):
            self.assertEqual(
                statuses.get(rule),
                "FAIL",
                f"{rule} expected FAIL, got {statuses.get(rule)!r}",
            )

    def test_strict_exit_codes(self) -> None:
        ok_path = FIXTURE_DIR / "reference_filled.md"
        proc_ok = subprocess.run(
            [sys.executable, str(TOOL), str(ok_path), "--strict"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc_ok.returncode, 0, proc_ok.stdout + proc_ok.stderr)

        bad_path = FIXTURE_DIR / "broken_filled.md"
        proc_bad = subprocess.run(
            [sys.executable, str(TOOL), str(bad_path), "--strict"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc_bad.returncode, 1, proc_bad.stdout + proc_bad.stderr)

    def test_json_out(self) -> None:
        import tempfile

        ok_path = FIXTURE_DIR / "reference_filled.md"
        out = Path(tempfile.gettempdir()) / "_impact_contract_validator_self_test.json"
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                str(ok_path),
                "--json-out",
                str(out),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue(out.is_file())
        doc = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(doc["fail_count"], 0)
        self.assertEqual(doc["schema"], "auditooor.impact_contract_validator.v1")


if __name__ == "__main__":
    unittest.main()
