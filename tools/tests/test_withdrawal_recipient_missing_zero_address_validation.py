from __future__ import annotations

import os
import py_compile
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
PATTERN = "withdrawal-recipient-missing-zero-address-validation"
DETECTOR = ROOT / "detectors" / "wave17" / "withdrawal_recipient_missing_zero_address_validation.py"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
CLASS_MAP = ROOT / "reference" / "detector_class_map_complete.yaml"
POSITIVE = ROOT / "patterns" / "fixtures" / f"{PATTERN}_vuln.sol"
CLEAN = ROOT / "patterns" / "fixtures" / f"{PATTERN}_clean.sol"
EXTERNAL_SAMPLE = Path("/Users/wolf/audits/polymarket/src/collateral/CollateralToken.sol")


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


class WithdrawalRecipientMissingZeroAddressValidationTest(unittest.TestCase):
    def _hits(self, fixture: Path) -> tuple[int, str]:
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
        return int(match.group(1)), proc.stdout

    def test_detector_reference_wiring(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        reference_text = REFERENCE.read_text(encoding="utf-8")
        class_map_text = CLASS_MAP.read_text(encoding="utf-8")

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("function.body_not_contains_regex", detector_text)
        self.assertIn("InvalidRecipient", detector_text)

        self.assertIn(f"pattern: {PATTERN}", reference_text)
        self.assertIn(f"fixtures:\n  vuln: patterns/fixtures/{PATTERN}_vuln.sol", reference_text)
        self.assertIn(f"  clean: patterns/fixtures/{PATTERN}_clean.sol", reference_text)
        self.assertIn(f"{PATTERN}:", class_map_text)
        self.assertIn("attack_class: missing-recipient-validation", class_map_text)

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        positive_hits, _ = self._hits(POSITIVE)
        clean_hits, _ = self._hits(CLEAN)
        self.assertEqual(positive_hits, 1)
        self.assertEqual(clean_hits, 0)

    def test_polymarket_collateral_external_sample_fires_when_available(self) -> None:
        if not EXTERNAL_SAMPLE.is_file():
            self.skipTest(f"external recall sample not present at {EXTERNAL_SAMPLE}")

        hits, stdout = self._hits(EXTERNAL_SAMPLE)
        source = EXTERNAL_SAMPLE.read_text(encoding="utf-8")
        self.assertGreaterEqual(hits, 1, stdout)
        self.assertIn("function unwrap(", source)
        self.assertIn("_to", source)


if __name__ == "__main__":
    unittest.main()
