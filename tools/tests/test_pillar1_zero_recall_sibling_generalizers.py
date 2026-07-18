from __future__ import annotations

import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"


CASES = [
    {
        "pattern": "optimistic-proposal-consumed-before-window",
        "attack_class": "optimistic-governor-poison",
        "positive": "detectors/fixtures/optimistic_proposal_consumed_before_window/positive.sol",
        "clean": "detectors/fixtures/optimistic_proposal_consumed_before_window/clean.sol",
        "origin": "detectors/fixtures/w68_optimistic_governor_poison_no_window/positive.sol",
        "positive_hits": 1,
        "origin_hits": 2,
    },
    {
        "pattern": "restricted-token-action-missing-registry-check",
        "attack_class": "token-freeze-bypass",
        "positive": "detectors/fixtures/restricted_token_action_missing_registry_check/positive.sol",
        "clean": "detectors/fixtures/restricted_token_action_missing_registry_check/clean.sol",
        "origin": "detectors/fixtures/w68_token_freeze_bypass_transfer/positive.sol",
        "positive_hits": 2,
        "origin_hits": 1,
    },
    {
        "pattern": "selector-target-binding-missing-authority",
        "attack_class": "selector-registration-bypass",
        "positive": "detectors/fixtures/selector_target_binding_missing_authority/positive.sol",
        "clean": "detectors/fixtures/selector_target_binding_missing_authority/clean.sol",
        "origin": "detectors/fixtures/w68_selector_registration_bypass_no_auth/positive/positive.sol",
        "positive_hits": 3,
        "origin_hits": 4,
    },
    {
        "pattern": "signed-approval-consumption-missing",
        "attack_class": "approval-replay",
        "positive": "detectors/fixtures/signed_approval_consumption_missing/positive.sol",
        "clean": "detectors/fixtures/signed_approval_consumption_missing/clean.sol",
        "origin": "detectors/fixtures/w68_approval_replay_missing_nonce/positive.sol",
        "positive_hits": 1,
        "origin_hits": 1,
    },
    {
        "pattern": "quorum-threshold-setter-missing-live-bounds",
        "attack_class": "veto-quorum-bypass",
        "positive": "detectors/fixtures/quorum_threshold_setter_missing_live_bounds/positive.sol",
        "clean": "detectors/fixtures/quorum_threshold_setter_missing_live_bounds/clean.sol",
        "origin": "detectors/fixtures/r74_abi_quorum_lost_after_manual_value_set/positive.sol",
        "positive_hits": 1,
        "origin_hits": 1,
    },
    {
        "pattern": "swap-pop-set-forward-remove-skip",
        "attack_class": "missing-last-element-validation",
        "positive": "detectors/fixtures/swap_pop_set_forward_remove_skip/positive.sol",
        "clean": "detectors/fixtures/swap_pop_set_forward_remove_skip/clean.sol",
        "origin": "patterns/fixtures/glider-enumerable-set-remove-iteration-skip_vuln.sol",
        "positive_hits": 1,
        "origin_hits": 1,
    },
]


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
                cwd=ROOT,
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


class Pillar1ZeroRecallSiblingGeneralizersTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.python = _python_with_slither()

    def _hits(self, pattern: str, rel_path: str) -> int:
        if self.python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [self.python, str(RUNNER), "--tier=ALL", str(ROOT / rel_path), pattern],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=180,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn(f"=== Running {pattern} ===", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_sibling_patterns_tag_the_expected_attack_class(self) -> None:
        for case in CASES:
            with self.subTest(pattern=case["pattern"]):
                spec = yaml.safe_load(
                    (ROOT / "reference" / "patterns.dsl" / f"{case['pattern']}.yaml").read_text(
                        encoding="utf-8"
                    )
                )
                self.assertIn(case["attack_class"], spec["tags"])

    def test_sibling_detectors_hit_positive_and_origin_but_not_clean(self) -> None:
        for case in CASES:
            pattern = case["pattern"]
            with self.subTest(pattern=pattern, fixture="positive"):
                self.assertEqual(self._hits(pattern, case["positive"]), case["positive_hits"])
            with self.subTest(pattern=pattern, fixture="clean"):
                self.assertEqual(self._hits(pattern, case["clean"]), 0)
            with self.subTest(pattern=pattern, fixture="origin"):
                self.assertEqual(self._hits(pattern, case["origin"]), case["origin_hits"])


if __name__ == "__main__":
    unittest.main()
