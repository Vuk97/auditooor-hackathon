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
PATTERN = "w68-optimistic-governor-poison-no-window"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "w68_optimistic_governor_poison_no_window"

REPLAY_CASES = [
    ("positive.sol", "clean.sol", 1),
    ("snapshot_vote_positive.sol", "snapshot_vote_clean.sol", 2),
    ("proposal_update_positive.sol", "proposal_update_clean.sol", 1),
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


class OptimisticGovernorPoisonRecallLiftTest(unittest.TestCase):
    def _hits(self, fixture_name: str) -> int:
        python = _python_with_slither()
        if python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [
                python,
                str(RUNNER),
                "--tier=ALL",
                str(FIXTURE_DIR / fixture_name),
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
        self.assertIn(PATTERN, proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_pattern_is_scoped_to_proposal_finalization_not_generic_execute(self) -> None:
        spec = yaml.safe_load(REFERENCE.read_text(encoding="utf-8"))
        matchers = "\n".join(str(row) for row in spec["match"])
        preconditions = "\n".join(str(row) for row in spec["preconditions"])

        self.assertIn("proposal|proposals", preconditions)
        self.assertIn("execute|executeProposal|finalize", matchers)
        self.assertIn("propose|createProposal|submitProposal|updateProposal", matchers)
        self.assertIn("castVote|vote|voteOnProposal", matchers)
        self.assertIn("set[A-Z]", matchers)
        self.assertIn("snapshot(Block)?", matchers)
        self.assertIn("balanceOf|getVotes", matchers)
        self.assertIn("proposal(State|Version|Nonce|Salt)", matchers)
        self.assertIn("getPastVotes", matchers)
        self.assertIn("voterNotice", matchers)
        self.assertIn("cancell?ed", matchers)

    def test_replay_fixture_pairs_fire_and_controls_stay_quiet(self) -> None:
        for positive, clean, min_hits in REPLAY_CASES:
            with self.subTest(positive=positive):
                self.assertGreaterEqual(self._hits(positive), min_hits)
            with self.subTest(clean=clean):
                self.assertEqual(self._hits(clean), 0)


if __name__ == "__main__":
    unittest.main()
