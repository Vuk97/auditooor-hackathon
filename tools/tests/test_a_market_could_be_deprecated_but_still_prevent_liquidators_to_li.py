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
PATTERN = "a-market-could-be-deprecated-but-still-prevent-liquidators-to-li"
FIXTURE_DIR = (
    ROOT
    / "detectors"
    / "fixtures"
    / "a_market_could_be_deprecated_but_still_prevent_liquidators_to_li"
)
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
DETECTOR = (
    ROOT
    / "detectors"
    / "wave17"
    / "a_market_could_be_deprecated_but_still_prevent_liquidators_to_li.py"
)
POSITIVE = FIXTURE_DIR / "ssi-fix-042_positive.sol"
CLEAN = FIXTURE_DIR / "ssi-fix-042_clean.sol"
SMOKE = FIXTURE_DIR / "ssi-fix-042_smoke.json"


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


class MarketDeprecationLiquidationPauseSmokeTests(unittest.TestCase):
    def _run(self, fixture: Path) -> tuple[int, str]:
        slither_python = _slither_python()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [slither_python, str(RUNNER), "--tier=ALL", str(fixture), PATTERN],
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
        return int(match.group(1)), proc.stdout

    def test_reference_yaml_points_at_owned_fixture_pair(self) -> None:
        text = REFERENCE.read_text(encoding="utf-8")
        self.assertIn(
            "vuln: detectors/fixtures/a_market_could_be_deprecated_but_still_prevent_liquidators_to_li/ssi-fix-042_positive.sol",
            text,
        )
        self.assertIn(
            "clean: detectors/fixtures/a_market_could_be_deprecated_but_still_prevent_liquidators_to_li/ssi-fix-042_clean.sol",
            text,
        )

    def test_generated_detector_uses_strict_supported_negated_call_predicate(self) -> None:
        text = DETECTOR.read_text(encoding="utf-8")
        self.assertIn("function.calls_function_matching", text)
        self.assertIn("'negate': True", text)
        self.assertNotIn("function.does_not_call_matching", text)

    def test_smoke_record_captures_positive_and_clean_counts(self) -> None:
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "passed_vulnerable_clean_smoke")
        self.assertGreaterEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        positive_hits, positive_output = self._run(POSITIVE)
        clean_hits, _ = self._run(CLEAN)
        self.assertGreaterEqual(positive_hits, 1)
        self.assertIn("pattern matched. See WIKI for details.", positive_output)
        self.assertEqual(clean_hits, 0)


if __name__ == "__main__":
    unittest.main()
