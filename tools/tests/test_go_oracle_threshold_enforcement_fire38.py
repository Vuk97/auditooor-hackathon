from __future__ import annotations

import os
import py_compile
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "lang-detect.py"
DETECTOR = ROOT / "detectors" / "go_wave1" / "go-oracle-threshold-enforcement-fire38.py"
FIXTURE_DIR = ROOT / "detectors" / "go_wave1" / "test_fixtures"
PATTERN = "go-oracle-threshold-enforcement-fire38"
POSITIVE = FIXTURE_DIR / "go_oracle_threshold_enforcement_fire38_positive.go"
NEGATIVE = FIXTURE_DIR / "go_oracle_threshold_enforcement_fire38_negative.go"


def _python_with_go_parser() -> str | None:
    candidates = [
        os.environ.get("AUDITOOOR_PYTHON_AST"),
        sys.executable,
        "python3",
        "python3.14",
        "python3.13",
        "python3.12",
        "python3.11",
    ]
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        try:
            probe = subprocess.run(
                [
                    candidate,
                    "-c",
                    "from tree_sitter_language_pack import get_parser; get_parser('go')",
                ],
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


class GoOracleThresholdEnforcementFire38Test(unittest.TestCase):
    def _hits(self, fixture: Path) -> tuple[int, str]:
        python_ast = _python_with_go_parser()
        if python_ast is None:
            self.skipTest("no Python interpreter can load the Go tree-sitter parser")

        with tempfile.NamedTemporaryFile(prefix=".go_oracle_threshold_enforcement_fire38_", suffix=".log") as tmp:
            proc = subprocess.run(
                [
                    python_ast,
                    str(TOOL),
                    "--lang",
                    "go",
                    str(FIXTURE_DIR),
                    "--only",
                    PATTERN,
                    "--file",
                    str(fixture),
                    "--log",
                    tmp.name,
                ],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=120,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout)
            match = re.search(r"total hits:\s*(\d+)", proc.stdout)
            self.assertIsNotNone(match, proc.stdout)
            log_text = Path(tmp.name).read_text(encoding="utf-8", errors="ignore")
            return int(match.group(1)), proc.stdout + "\n" + log_text

    def test_detector_compiles_and_declares_provenance(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        detector = DETECTOR.read_text(encoding="utf-8")
        self.assertIn('DETECTOR_ID = "go_wave1.go-oracle-threshold-enforcement-fire38"', detector)
        self.assertIn("verification_tier: tier-3-synthetic-taxonomy-anchored", detector)
        self.assertIn("attack_class: oracle-price-manipulation", detector)
        self.assertIn("reports/detector_lift_fire37_20260605/post_priorities_go.md", detector)
        self.assertIn("go-oracle-threshold-stale-fire33.py", detector)
        self.assertIn("go-oracle-threshold-staleness-fire36.py", detector)
        self.assertIn(".auditooor/memory_context_receipt.json", detector)
        self.assertIn("NOT_SUBMIT_READY", detector)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        positive_hits, positive_log = self._hits(POSITIVE)
        negative_hits, negative_log = self._hits(NEGATIVE)
        self.assertEqual(positive_hits, 5, positive_log)
        self.assertEqual(negative_hits, 0, negative_log)
        self.assertIn("ReturnPriceWithConfiguredMaxAgeButNoGuard", positive_log)
        self.assertIn("StorePriceBeforeAnsweredRoundGuard", positive_log)
        self.assertIn("StorePriceWithUnusedVersionCheck", positive_log)
        self.assertIn("StoreThresholdBeforeTimestampGuard", positive_log)
        self.assertIn("StoreRiskPriceWithLoadedThresholdsButNoReject", positive_log)
        self.assertIn("oracle-price-manipulation", positive_log)
        self.assertIn("NOT_SUBMIT_READY", positive_log)

    def test_false_positive_boundaries_are_locked(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        negative = NEGATIVE.read_text(encoding="utf-8")
        detector = DETECTOR.read_text(encoding="utf-8")
        for path in (DETECTOR, POSITIVE, NEGATIVE, Path(__file__)):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("\u2014", text)
            self.assertNotIn("\u2013", text)

        self.assertIn("maxAge := k.maxAgeByMarket[market]", positive)
        self.assertIn("answeredRoundOK := report.AnsweredInRound >= report.RoundID", positive)
        self.assertIn("versionMatches := report.Version == expectedVersion", positive)
        self.assertIn("if report.Timestamp < maxTimestamp", positive)
        self.assertIn("bounds := k.oracleBounds[pair]", positive)

        self.assertIn("if ctx.BlockTimeUnix()-report.UpdatedAt > maxAge", negative)
        self.assertIn("if report.AnsweredInRound < report.RoundID", negative)
        self.assertIn("if report.Version != expectedVersion", negative)
        self.assertIn("if err := k.ValidateOracleRound(ctx, report, pair); err != nil", negative)
        self.assertIn("StoreOracleMetricOnly", negative)
        self.assertIn("R40 and R80 proof still require", detector)


if __name__ == "__main__":
    unittest.main()
