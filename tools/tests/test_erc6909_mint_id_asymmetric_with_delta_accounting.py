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
PATTERN = "erc6909-mint-id-asymmetric-with-delta-accounting"
DETECTOR = ROOT / "detectors" / "wave17" / "erc6909_mint_id_asymmetric_with_delta_accounting.py"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "erc6909_mint_id_asymmetric_with_delta_accounting"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
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


class Erc6909MintIdAsymmetricWithDeltaAccountingTest(unittest.TestCase):
    def _hits(self, fixture: Path) -> int:
        slither_python = _python_with_slither()
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
        self.assertIn(PATTERN, proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_reference_yaml_points_at_owned_fixture_pair(self) -> None:
        reference = REFERENCE.read_text(encoding="utf-8")
        detector = DETECTOR.read_text(encoding="utf-8")

        self.assertIn(
            "vuln: detectors/fixtures/erc6909_mint_id_asymmetric_with_delta_accounting/positive.sol",
            reference,
        )
        self.assertIn(
            "clean: detectors/fixtures/erc6909_mint_id_asymmetric_with_delta_accounting/clean.sol",
            reference,
        )
        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector)
        self.assertIn("CurrencyLibrary.fromId(id)", detector)

    def test_fixture_pair_models_raw_id_and_normalized_id_paths(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        clean = CLEAN.read_text(encoding="utf-8")

        self.assertIn("_accountDelta(CurrencyLibrary.fromId(id), -int256(amount));", positive)
        self.assertIn("_mint(to, id, amount);", positive)
        self.assertIn("uint256 normalizedId = CurrencyLibrary.toId(currency);", clean)
        self.assertIn("_mint(to, normalizedId, amount);", clean)

    def test_smoke_record_captures_positive_and_clean_counts(self) -> None:
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))
        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertGreaterEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertGreaterEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
