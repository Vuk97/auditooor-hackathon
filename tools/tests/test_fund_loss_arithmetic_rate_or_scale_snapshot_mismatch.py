from __future__ import annotations

import importlib.util
import os
import py_compile
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
PATTERN = "fund-loss-arithmetic-rate-or-scale-snapshot-mismatch"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
DETECTOR = ROOT / "detectors" / "wave18" / "fund_loss_arithmetic_rate_or_scale_snapshot_mismatch.py"
POSITIVE = ROOT / "patterns" / "fixtures" / f"{PATTERN}_vuln.sol"
CLEAN = ROOT / "patterns" / "fixtures" / f"{PATTERN}_clean.sol"
EC_CONFIRMED = ROOT / "patterns" / "fixtures" / "ec-borrow-supply-rate-snapshot-mismatch_vuln.sol"
FEE_CONFIRMED = ROOT / "detectors" / "fixtures" / "fee_redirect_user_controlled_sink" / "positive.sol"
PATTERN_COMPILE = ROOT / "tools" / "pattern-compile.py"
CLASSIFIER_TOOL = ROOT / "tools" / "audit" / "detector-class-map-builder.py"
BACKTEST_TOOL = ROOT / "tools" / "audit" / "detector-catch-rate-backtest.py"


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


class FundLossArithmeticRateOrScaleSnapshotMismatchTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.compiler = _load_module(PATTERN_COMPILE, "pattern_compile_fa_fire5")
        cls.classifier = _load_module(CLASSIFIER_TOOL, "detector_class_map_builder_fa_fire5")
        cls.backtest = _load_module(BACKTEST_TOOL, "detector_catch_rate_backtest_fa_fire5")
        cls.spec = yaml.safe_load(REFERENCE.read_text(encoding="utf-8"))

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
        self.assertIn(f"=== Running {PATTERN} ===", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1)), proc.stdout

    def test_yaml_metadata_and_strict_compile(self) -> None:
        self.assertEqual(self.spec["pattern"], PATTERN)
        self.assertEqual(self.spec["fixtures"]["vuln"], str(POSITIVE.relative_to(ROOT)))
        self.assertEqual(self.spec["fixtures"]["clean"], str(CLEAN.relative_to(ROOT)))
        self.assertIn("fund-loss-via-arithmetic", self.spec["tags"])

        classified = self.classifier.classify_pattern(self.spec, PATTERN)
        self.assertEqual(classified["attack_class"], "fund-loss-via-arithmetic")
        self.assertEqual(
            self.backtest.derive_attack_class(PATTERN, self.spec["tags"]),
            "fund-loss-via-arithmetic",
        )

        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            ok = self.compiler.compile_pattern(
                REFERENCE,
                Path(tmp) / "wave18",
                strict_yaml_shapes=True,
                strict_unsupported_keys=True,
            )
        self.assertTrue(ok)

        py_compile.compile(str(DETECTOR), doraise=True)
        detector_text = DETECTOR.read_text(encoding="utf-8")
        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("stale-rate-snapshot", REFERENCE.read_text(encoding="utf-8"))
        self.assertIn("fee-state-sink-mismatch", REFERENCE.read_text(encoding="utf-8"))

    def test_fixture_sources_encode_positive_and_clean_branches(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        clean = CLEAN.read_text(encoding="utf-8")

        self.assertIn("borrow = getBorrowRate();", positive)
        self.assertIn("supply = getSupplyRate();", positive)
        self.assertIn("assets = shares / exchangeRate * 1e18;", positive)
        self.assertIn("token.safeTransfer(feeRecipient, feeAmount);", positive)

        self.assertIn("accrueInterest();", clean)
        self.assertIn("MathLike.mulDiv(shares, 1e18, exchangeRate)", clean)
        self.assertIn("require(assets > 0", clean)
        self.assertIn("token.safeTransfer(treasury, feeAmount);", clean)

    def test_positive_fixture_fires_and_clean_fixture_is_silent(self) -> None:
        positive_hits, positive_output = self._hits(POSITIVE)
        clean_hits, clean_output = self._hits(CLEAN)

        self.assertGreaterEqual(positive_hits, 3, positive_output)
        self.assertEqual(clean_hits, 0, clean_output)

    def test_confirmed_start_samples_are_caught(self) -> None:
        ec_hits, ec_output = self._hits(EC_CONFIRMED)
        fee_hits, fee_output = self._hits(FEE_CONFIRMED)

        self.assertGreaterEqual(ec_hits, 1, ec_output)
        self.assertGreaterEqual(fee_hits, 1, fee_output)


if __name__ == "__main__":
    unittest.main()
