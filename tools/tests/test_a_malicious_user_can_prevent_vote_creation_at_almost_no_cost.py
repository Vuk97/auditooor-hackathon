from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
PATTERN = "a-malicious-user-can-prevent-vote-creation-at-almost-no-cost"
FIXTURE_DIR = (
    ROOT
    / "detectors"
    / "fixtures"
    / "a_malicious_user_can_prevent_vote_creation_at_almost_no_cost"
)
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
POSITIVE = FIXTURE_DIR / "ssi-fix-039_positive.sol"
CLEAN = FIXTURE_DIR / "ssi-fix-039_clean.sol"
SMOKE = FIXTURE_DIR / "ssi-fix-039_smoke.json"


def _slither_python() -> str | None:
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
        proc = subprocess.run(
            [candidate, "-c", "import slither; import slither.detectors.abstract_detector"],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if proc.returncode == 0:
            return candidate
    return None


@unittest.skipUnless(_slither_python(), "slither-enabled python is not available")
class MaliciousUserPreventVoteCreationSmokeTests(unittest.TestCase):
    def _hits(self, fixture: Path) -> int:
        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [_slither_python() or "python3", str(RUNNER), "--tier=ALL", str(fixture), PATTERN],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertNotIn("UNKNOWN function predicate key", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_reference_yaml_points_at_owned_fixture_pair(self) -> None:
        text = REFERENCE.read_text(encoding="utf-8")
        self.assertIn(
            "vuln: detectors/fixtures/a_malicious_user_can_prevent_vote_creation_at_almost_no_cost/ssi-fix-039_positive.sol",
            text,
        )
        self.assertIn(
            "clean: detectors/fixtures/a_malicious_user_can_prevent_vote_creation_at_almost_no_cost/ssi-fix-039_clean.sol",
            text,
        )

    def test_smoke_record_is_consistent(self) -> None:
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))
        self.assertEqual(payload.get("status"), "passed_vulnerable_clean_smoke")
        self.assertGreater(payload.get("positive_hits", 0), 0)
        self.assertEqual(payload.get("clean_hits"), 0)

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertGreaterEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
