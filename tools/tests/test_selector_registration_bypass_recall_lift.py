from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
REPO = ROOT
YAML_PATH = REPO / "reference" / "patterns.dsl" / "w68-selector-registration-bypass-no-auth.yaml"
RUN_CUSTOM = REPO / "detectors" / "run_custom.py"
DETECTOR = "w68-selector-registration-bypass-no-auth"
FIXTURE_ROOT = REPO / "detectors" / "fixtures" / "w68_selector_registration_bypass_no_auth"


def _python_with_slither() -> str | None:
    candidates = [
        os.environ.get("SLITHER_PYTHON"),
        sys.executable,
        "/opt/homebrew/opt/python@3.14/bin/python3.14",
        "/opt/homebrew/opt/python@3.13/bin/python3.13",
        "/opt/homebrew/bin/python3.13",
    ]
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        try:
            proc = subprocess.run(
                [candidate, "-c", "import slither; import slither.detectors.abstract_detector"],
                cwd=REPO,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode == 0:
            return candidate
    return None


class SelectorRegistrationBypassRecallLiftTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.spec = yaml.safe_load(YAML_PATH.read_text(encoding="utf-8"))

    def test_yaml_broadens_selector_registry_shape_without_auth(self) -> None:
        self.assertEqual(self.spec["pattern"], DETECTOR)
        self.assertEqual(
            self.spec["fixtures"]["vuln"],
            "detectors/fixtures/w68_selector_registration_bypass_no_auth/positive/positive.sol",
        )
        self.assertEqual(
            self.spec["fixtures"]["clean"],
            "detectors/fixtures/w68_selector_registration_bypass_no_auth/clean/clean.sol",
        )

        match_predicates = self.spec["match"]
        self.assertTrue(
            any(
                isinstance(entry, dict) and "function.writes_state_var_matching_regex" in entry
                for entry in match_predicates
            ),
            "expected function.writes_state_var_matching_regex in the widened selector-registration rule",
        )
        self.assertTrue(
            any(
                isinstance(entry, dict)
                and "function.name_matches" in entry
                and "set|enable|route|bind|execute" in entry["function.name_matches"]
                for entry in match_predicates
            ),
            "expected selector/module/action/wrapper verbs in the widened selector-registration rule",
        )
        self.assertTrue(
            any(
                isinstance(entry, dict)
                and "function.writes_state_var_matching_regex" in entry
                and "action" in entry["function.writes_state_var_matching_regex"]
                for entry in match_predicates
            ),
            "expected action registration state writes in the widened selector-registration rule",
        )
        self.assertIn("registrar", self.spec["help"].lower())
        self.assertIn("registrar", self.spec["wiki_description"].lower())

    def test_broad_fixture_hits_positive_and_keeps_owner_gated_clean(self) -> None:
        python = _python_with_slither()
        if python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"

        positive_file = FIXTURE_ROOT / "positive" / "positive.sol"
        clean_file = FIXTURE_ROOT / "clean" / "clean.sol"

        for target_file, expected_hits in ((positive_file, 4), (clean_file, 0)):
            with self.subTest(target=target_file.name):
                proc = subprocess.run(
                    [
                        python,
                        str(RUN_CUSTOM),
                        "--tier=ALL",
                        str(target_file),
                        DETECTOR,
                    ],
                    cwd=REPO,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=180,
                )
                self.assertEqual(proc.returncode, 0, proc.stdout)
                self.assertIn("[ok] loaded 1 custom detector(s)", proc.stdout)
                self.assertIn(f"=== Running {DETECTOR} ===", proc.stdout)
                self.assertIn(f"[done] total hits: {expected_hits}", proc.stdout)

    def test_registrar_fixture_hits_wrong_registrar_and_owner_gate_stays_clean(self) -> None:
        python = _python_with_slither()
        if python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"

        registrar_positive = FIXTURE_ROOT / "positive" / "registrar.sol"
        registrar_clean = FIXTURE_ROOT / "clean" / "registrar.sol"

        for target_file, expected_hits in ((registrar_positive, 2), (registrar_clean, 0)):
            with self.subTest(target=target_file.name):
                proc = subprocess.run(
                    [
                        python,
                        str(RUN_CUSTOM),
                        "--tier=ALL",
                        str(target_file),
                        DETECTOR,
                    ],
                    cwd=REPO,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=180,
                )
                self.assertEqual(proc.returncode, 0, proc.stdout)
                self.assertIn("[ok] loaded 1 custom detector(s)", proc.stdout)
                self.assertIn(f"=== Running {DETECTOR} ===", proc.stdout)
                self.assertIn(f"[done] total hits: {expected_hits}", proc.stdout)


if __name__ == "__main__":
    unittest.main()
