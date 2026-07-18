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
DETECTOR = ROOT / "detectors" / "go_wave1" / "go-oracle-price-threshold-stale-fire32.py"
FIXTURE_DIR = ROOT / "detectors" / "go_wave1" / "test_fixtures"
PATTERN = "go-oracle-price-threshold-stale-fire32"
POSITIVE = FIXTURE_DIR / f"{PATTERN}_positive.go"
NEGATIVE = FIXTURE_DIR / f"{PATTERN}_negative.go"


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


class GoOraclePriceThresholdStaleFire32Test(unittest.TestCase):
    def _hits(self, fixture: Path) -> tuple[int, str]:
        python_ast = _python_with_go_parser()
        if python_ast is None:
            self.skipTest("no Python interpreter can load the Go tree-sitter parser")

        with tempfile.NamedTemporaryFile(prefix=".go_oracle_price_threshold_", suffix=".log") as tmp:
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
            return int(match.group(1)), log_text

    def test_detector_compiles_and_keeps_ascii_dash_discipline(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        for path in (DETECTOR, POSITIVE, NEGATIVE, Path(__file__)):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("\u2014", text)
            self.assertNotIn("\u2013", text)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        positive_hits, positive_log = self._hits(POSITIVE)
        negative_hits, negative_log = self._hits(NEGATIVE)
        self.assertEqual(positive_hits, 3, positive_log)
        self.assertEqual(negative_hits, 0, negative_log)
        self.assertIn("LiquidateWithDeviationOnly", positive_log)
        self.assertIn("OpenMarginWithTimestampOnly", positive_log)
        self.assertIn("SettleFundingWithSourceOnly", positive_log)
        self.assertIn("oracle-price-manipulation", positive_log)

    def test_false_positive_boundaries_are_locked(self) -> None:
        clean = NEGATIVE.read_text(encoding="utf-8")
        self.assertIn("price.SourceID != k.trustedSourceID", clean)
        self.assertIn("ctx.BlockTime().Sub(price.UpdatedAt) > k.maxAge", clean)
        self.assertIn("deviationBps(price.Value, position.LastPrice) > k.maxDeviationBps", clean)
        self.assertIn("GetOraclePriceAge", clean)
        self.assertIn("ReadUnvalidatedPriceForTelemetry", clean)
        self.assertIn("StoreDeviationMetric", clean)


if __name__ == "__main__":
    unittest.main()
