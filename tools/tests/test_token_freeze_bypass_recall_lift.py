from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

import yaml


REPO = Path(__file__).resolve().parents[2]
DSL = REPO / "reference" / "patterns.dsl" / "w68-token-freeze-bypass-transfer.yaml"
PATTERN = "w68-token-freeze-bypass-transfer"
RUN_CUSTOM = REPO / "detectors" / "run_custom.py"
FIX_DIR = REPO / "detectors" / "fixtures" / "w68_token_freeze_bypass_transfer"


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


class TokenFreezeBypassRecallLiftTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.spec = yaml.safe_load(DSL.read_text(encoding="utf-8"))

    def test_dsl_is_generalized_beyond_transfer_only(self) -> None:
        spec = self.spec
        self.assertEqual(spec["pattern"], PATTERN)
        self.assertEqual(
            spec["fixtures"]["vuln"],
            "detectors/fixtures/w68_token_freeze_bypass_transfer/positive.sol",
        )
        self.assertEqual(
            spec["fixtures"]["clean"],
            "detectors/fixtures/w68_token_freeze_bypass_transfer/clean.sol",
        )

        name_match = spec["match"][0]["function.name_matches"]
        body_match = spec["match"][3]["function.body_contains_regex"]
        guard_reject = spec["match"][4]["function.body_not_contains_regex"]
        source_precondition = spec["preconditions"][0]["contract.source_matches_regex"]

        self.assertIn("transfer", name_match)
        self.assertIn("move", name_match)
        self.assertIn("burn", name_match)
        self.assertIn("approve", name_match)
        self.assertIn("ragequit", name_match)
        self.assertIn("execute", name_match)
        self.assertIn("join", name_match)
        self.assertIn("leavePool", name_match)
        self.assertIn("exitPool", name_match)
        self.assertIn("frozen|blocked|vetoed", source_precondition)
        self.assertIn("allowance", body_match)
        self.assertIn("shares", body_match)
        self.assertIn("frozen|blocked|vetoed", guard_reject)

    def test_fixture_pack_exists(self) -> None:
        for rel in (
            "positive.sol",
            "clean.sol",
            "move_positive.sol",
            "move_clean.sol",
            "burn_positive.sol",
            "burn_clean.sol",
            "approval_positive.sol",
            "approval_clean.sol",
            "ragequit_positive.sol",
            "ragequit_clean.sol",
            "execute_join_positive.sol",
            "execute_join_clean.sol",
            "leave_pool_positive.sol",
            "leave_pool_clean.sol",
        ):
            with self.subTest(rel=rel):
                self.assertTrue((FIX_DIR / rel).is_file(), rel)

    def test_detector_hits_positive_variants_and_skips_cleans(self) -> None:
        python = _python_with_slither()
        if python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"

        cases = [
            ("positive.sol", 1),
            ("clean.sol", 0),
            ("move_positive.sol", 1),
            ("move_clean.sol", 0),
            ("burn_positive.sol", 1),
            ("burn_clean.sol", 0),
            ("approval_positive.sol", 1),
            ("approval_clean.sol", 0),
            ("ragequit_positive.sol", 1),
            ("ragequit_clean.sol", 0),
            ("execute_join_positive.sol", 1),
            ("execute_join_clean.sol", 0),
            ("leave_pool_positive.sol", 1),
            ("leave_pool_clean.sol", 0),
        ]

        for fixture_name, expected_hits in cases:
            with self.subTest(fixture=fixture_name):
                proc = subprocess.run(
                    [
                        python,
                        str(RUN_CUSTOM),
                        "--tier=ALL",
                        str(FIX_DIR / fixture_name),
                        PATTERN,
                    ],
                    cwd=REPO,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=120,
                )
                self.assertEqual(proc.returncode, 0, proc.stdout)
                self.assertIn("[ok] loaded 1 custom detector(s)", proc.stdout)
                self.assertIn(f"=== Running {PATTERN} ===", proc.stdout)
                self.assertIn(f"[done] total hits: {expected_hits}", proc.stdout)


if __name__ == "__main__":
    unittest.main()
