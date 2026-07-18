from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ARGUMENT = "claimreward-does-not-verify-token-ownership"
RUNNER = ROOT / "detectors" / "run_custom.py"
SPEC = ROOT / "detectors" / "_specs" / "drafts_glider" / f"{ARGUMENT}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "wave13_broken"
POSITIVE = FIXTURE_DIR / "claimreward_does_not_verify_token_ownership_vulnerable.sol"
CLEAN = FIXTURE_DIR / "claimreward_does_not_verify_token_ownership_clean.sol"
SMOKE = FIXTURE_DIR / "claimreward_does_not_verify_token_ownership_smoke.json"


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


class ClaimrewardDoesNotVerifyTokenOwnershipTest(unittest.TestCase):
    def _hits(self, fixture: Path) -> int:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [
                slither_python,
                str(RUNNER),
                "--include-graveyard",
                "--tier=ALL",
                str(fixture),
                ARGUMENT,
            ],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertNotIn("UNKNOWN function predicate key", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_draft_spec_uses_ownership_guard_for_clean_fixture(self) -> None:
        text = SPEC.read_text(encoding="utf-8")
        self.assertIn("guarded_helper_name: \"_checkOwnership\"", text)
        self.assertIn("vuln_fn_params: \"uint256 tokenId\"", text)
        self.assertIn("checkOwnership", text)

    def test_smoke_record_captures_positive_and_clean_counts(self) -> None:
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "passed_vulnerable_clean_smoke")
        self.assertEqual(
            payload["vulnerable_fixture"],
            "detectors/wave13_broken/claimreward_does_not_verify_token_ownership_vulnerable.sol",
        )
        self.assertEqual(
            payload["clean_fixture"],
            "detectors/wave13_broken/claimreward_does_not_verify_token_ownership_clean.sol",
        )
        self.assertGreaterEqual(payload["vulnerable_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertGreaterEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
