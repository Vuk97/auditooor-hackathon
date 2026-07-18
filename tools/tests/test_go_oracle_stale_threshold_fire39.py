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
DETECTOR = ROOT / "detectors" / "go_wave1" / "go-oracle-stale-threshold-fire39.py"
FIXTURE_DIR = ROOT / "detectors" / "go_wave1" / "test_fixtures"
PATTERN = "go-oracle-stale-threshold-fire39"
POSITIVE = FIXTURE_DIR / "go_oracle_stale_threshold_fire39_positive.go"
NEGATIVE = FIXTURE_DIR / "go_oracle_stale_threshold_fire39_negative.go"
FIRE33_POSITIVE = FIXTURE_DIR / "go-oracle-threshold-stale-fire33_positive.go"


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


class GoOracleStaleThresholdFire39Test(unittest.TestCase):
    def _hits(self, fixture: Path) -> tuple[int, str]:
        python_ast = _python_with_go_parser()
        if python_ast is None:
            self.skipTest("no Python interpreter can load the Go tree-sitter parser")

        with tempfile.NamedTemporaryFile(prefix=".go_oracle_stale_threshold_fire39_", suffix=".log") as tmp:
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
        self.assertIn('DETECTOR_ID = "go_wave1.go-oracle-stale-threshold-fire39"', detector)
        self.assertIn("verification_tier: tier-3-synthetic-taxonomy-anchored", detector)
        self.assertIn("attack_class: oracle-price-manipulation", detector)
        self.assertIn("context_pack_id: auditooor.vault_context_pack.v1:resume:cbdd9eeb5255863c", detector)
        self.assertIn("context_pack_hash: cbdd9eeb5255863c4870d83e88642e9c4a3eef8e7cdfb8b5fb9a8ee7ac5a25d8", detector)
        self.assertIn("MCP receipt: .auditooor/memory_context_receipt.json", detector)
        self.assertIn("NOT_SUBMIT_READY", detector)
        self.assertIn("R40/R76/R80 caveat", detector)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        positive_hits, positive_log = self._hits(POSITIVE)
        negative_hits, negative_log = self._hits(NEGATIVE)
        self.assertEqual(positive_hits, 4, positive_log)
        self.assertEqual(negative_hits, 0, negative_log)
        self.assertIn("SettleLiquidationWithConfidenceOnly", positive_log)
        self.assertIn("UpdateReserveFromStaleThreshold", positive_log)
        self.assertIn("SettleFundingBeforeRoundFreshness", positive_log)
        self.assertIn("OpenMarginWithConfiguredMaxAgeButNoCheck", positive_log)
        self.assertIn("oracle-price-manipulation", positive_log)
        self.assertIn("NOT_SUBMIT_READY", positive_log)

    def test_fire33_recall_miss_sample_is_now_detected(self) -> None:
        hits, log = self._hits(FIRE33_POSITIVE)
        self.assertGreaterEqual(hits, 1, log)
        self.assertIn("SettleLiquidationFromRawOracle", log)

    def test_semantic_boundary_and_false_positive_guards_are_locked(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        negative = NEGATIVE.read_text(encoding="utf-8")
        detector = DETECTOR.read_text(encoding="utf-8")
        for path in (DETECTOR, POSITIVE, NEGATIVE, Path(__file__)):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("\u2014", text)
            self.assertNotIn("\u2013", text)

        self.assertIn("if report.Confidence > k.maxConfidence", positive)
        self.assertIn("if threshold.Threshold <= 0", positive)
        self.assertIn("if round.AnsweredInRound < round.RoundID", positive)
        self.assertIn("_ = k.maxAge", positive)

        self.assertIn("ctx.BlockTimeUnix()-report.UpdatedAt > k.maxAge", negative)
        self.assertIn("ValidateFreshOracleThreshold", negative)
        self.assertIn("if round.AnsweredInRound < round.RoundID", negative)
        self.assertIn("if median.PairID != asset", negative)
        self.assertIn("StoreOracleMetricOnly", negative)

        self.assertIn("_build_source_model", detector)
        self.assertIn("_has_freshness_guard", detector)
        self.assertIn("timestamp-bearing oracle data", detector)


if __name__ == "__main__":
    unittest.main()

