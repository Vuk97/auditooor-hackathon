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
DETECTOR = ROOT / "detectors" / "go_wave1" / "go-oracle-threshold-staleness-fire36.py"
FIXTURE_DIR = ROOT / "detectors" / "go_wave1" / "test_fixtures"
PATTERN = "go-oracle-threshold-staleness-fire36"
POSITIVE = FIXTURE_DIR / "go_oracle_threshold_staleness_fire36_positive.go"
NEGATIVE = FIXTURE_DIR / "go_oracle_threshold_staleness_fire36_negative.go"


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


class GoOracleThresholdStalenessFire36Test(unittest.TestCase):
    def _hits(self, fixture: Path) -> tuple[int, str]:
        python_ast = _python_with_go_parser()
        if python_ast is None:
            self.skipTest("no Python interpreter can load the Go tree-sitter parser")

        with tempfile.NamedTemporaryFile(prefix=".go_oracle_threshold_staleness_fire36_", suffix=".log") as tmp:
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
        self.assertIn('DETECTOR_ID = "go_wave1.go-oracle-threshold-staleness-fire36"', detector)
        self.assertIn("verification_tier: tier-3-synthetic-taxonomy-anchored", detector)
        self.assertIn("attack_class: oracle-price-manipulation", detector)
        self.assertIn("reports/detector_lift_fire35_20260605/post_priorities_go.md", detector)
        self.assertIn("reference/patterns.dsl.r74_mined_cs/oracle-price-manipulation.yaml", detector)
        self.assertIn("go-oracle-pair-binding-fire35.py", detector)
        self.assertIn("go-oracle-threshold-stale-fire33.py", detector)
        self.assertIn("NOT_SUBMIT_READY", detector)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        positive_hits, positive_log = self._hits(POSITIVE)
        negative_hits, negative_log = self._hits(NEGATIVE)
        self.assertEqual(positive_hits, 4, positive_log)
        self.assertEqual(negative_hits, 0, negative_log)
        self.assertIn("UpdatePairPriceWithDeviationButNoFreshness", positive_log)
        self.assertIn("AcceptMedianWithMinOnlyBound", positive_log)
        self.assertIn("UpdateThresholdWithGlobalBaseline", positive_log)
        self.assertIn("UpdateRiskPriceAfterBaselineMutation", positive_log)
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

        self.assertIn("if report.PairID != pair", positive)
        self.assertIn("if median.Price < k.minPrice", positive)
        self.assertIn("absDiff(report.Price, k.lastPrice)", positive)
        self.assertIn("k.lastPrices[pair] = report.Price", positive)

        self.assertIn("ctx.BlockTimeUnix()-report.UpdatedAt > k.maxAge", negative)
        self.assertIn("if report.Price < k.minPrice", negative)
        self.assertIn("if report.Price > k.maxPrice", negative)
        self.assertIn("absDiff(report.Price, k.lastPrices[pair])", negative)
        self.assertIn("oldPrice := k.lastPrices[pair]", negative)
        self.assertIn("StoreOracleMetric", negative)
        self.assertIn("R40 and R80 proof still require", detector)


if __name__ == "__main__":
    unittest.main()
