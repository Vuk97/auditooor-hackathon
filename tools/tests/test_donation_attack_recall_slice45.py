from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
PATTERN = "ec-donation-inflates-share-price"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
VULN = ROOT / "patterns" / "fixtures" / f"{PATTERN}_vuln.sol"
CLEAN = ROOT / "patterns" / "fixtures" / f"{PATTERN}_clean.sol"
GUARDED_CLEAN = ROOT / "patterns" / "fixtures" / f"{PATTERN}_guarded_clean.sol"
PATTERN_COMPILE = ROOT / "tools" / "pattern-compile.py"
CLASSIFIER_TOOL = ROOT / "tools" / "audit" / "detector-class-map-builder.py"
BACKTEST_TOOL = ROOT / "tools" / "audit" / "detector-catch-rate-backtest.py"
RUN_CUSTOM = ROOT / "detectors" / "run_custom.py"
W68_PATTERN = "w68-share-price-manipulation-donation"
W68_REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{W68_PATTERN}.yaml"
W68_VULN = ROOT / "detectors" / "fixtures" / "w68_zero_coverage" / "share_price_manipulation_positive.sol"
W68_CLEAN = ROOT / "detectors" / "fixtures" / "w68_zero_coverage" / "share_price_manipulation_clean.sol"


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


class DonationAttackRecallSlice45Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.compiler = _load_module(PATTERN_COMPILE, "pattern_compile")
        cls.classifier = _load_module(CLASSIFIER_TOOL, "detector_class_map_builder")
        cls.backtest = _load_module(BACKTEST_TOOL, "detector_catch_rate_backtest")

    def test_pattern_compiles_under_strict_guards(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            ok = self.compiler.compile_pattern(
                REFERENCE,
                Path(tmp) / "wave17",
                strict_yaml_shapes=True,
                strict_unsupported_keys=True,
            )
        self.assertTrue(ok)

    def test_taxonomy_maps_to_donation_attack(self) -> None:
        spec = yaml.safe_load(REFERENCE.read_text(encoding="utf-8"))
        self.assertEqual(
            self.classifier.classify_pattern(spec, PATTERN)["attack_class"],
            "donation-attack",
        )
        self.assertEqual(
            self.backtest.derive_attack_class(PATTERN, spec.get("tags")),
            "donation-attack",
        )

    def test_w68_sibling_taxonomy_maps_to_donation_attack(self) -> None:
        spec = yaml.safe_load(W68_REFERENCE.read_text(encoding="utf-8"))
        self.assertEqual(
            self.classifier.classify_pattern(spec, W68_PATTERN)["attack_class"],
            "donation-attack",
        )
        self.assertEqual(
            self.backtest.derive_attack_class(W68_PATTERN, spec.get("tags")),
            "donation-attack",
        )

    def test_direct_pattern_runner_positive_fires_and_clean_stays_quiet(self) -> None:
        if _python_with_slither() is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        engine = self.backtest._import_engine()
        spec = yaml.safe_load(REFERENCE.read_text(encoding="utf-8"))

        positive_hits, positive_error = self.backtest.run_pattern_on_file(spec, VULN, engine)
        self.assertIsNone(positive_error)
        self.assertEqual(positive_hits, 1)

        clean_hits, clean_error = self.backtest.run_pattern_on_file(spec, CLEAN, engine)
        self.assertIsNone(clean_error)
        self.assertEqual(clean_hits, 0)

        guarded_clean_hits, guarded_clean_error = self.backtest.run_pattern_on_file(
            spec,
            GUARDED_CLEAN,
            engine,
        )
        self.assertIsNone(guarded_clean_error)
        self.assertEqual(guarded_clean_hits, 0)

    def test_w68_sibling_catches_totalassets_donation_and_clean_stays_quiet(self) -> None:
        if _python_with_slither() is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        engine = self.backtest._import_engine()
        spec = yaml.safe_load(W68_REFERENCE.read_text(encoding="utf-8"))

        sibling_hits, sibling_error = self.backtest.run_pattern_on_file(spec, VULN, engine)
        self.assertIsNone(sibling_error)
        self.assertGreater(sibling_hits, 0)

        own_positive_hits, own_positive_error = self.backtest.run_pattern_on_file(spec, W68_VULN, engine)
        self.assertIsNone(own_positive_error)
        self.assertGreater(own_positive_hits, 0)

        donation_clean_hits, donation_clean_error = self.backtest.run_pattern_on_file(spec, CLEAN, engine)
        self.assertIsNone(donation_clean_error)
        self.assertEqual(donation_clean_hits, 0)

        guarded_clean_hits, guarded_clean_error = self.backtest.run_pattern_on_file(
            spec,
            GUARDED_CLEAN,
            engine,
        )
        self.assertIsNone(guarded_clean_error)
        self.assertEqual(guarded_clean_hits, 0)

        own_clean_hits, own_clean_error = self.backtest.run_pattern_on_file(spec, W68_CLEAN, engine)
        self.assertIsNone(own_clean_error)
        self.assertEqual(own_clean_hits, 0)

    def test_run_custom_sees_generated_detector(self) -> None:
        python = _python_with_slither()
        if python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        for path, expected_hits in ((VULN, 1), (CLEAN, 0), (GUARDED_CLEAN, 0)):
            with self.subTest(path=path.name):
                proc = subprocess.run(
                    [
                        python,
                        str(RUN_CUSTOM),
                        "--tier=ALL",
                        str(path),
                        PATTERN,
                    ],
                    cwd=ROOT,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=120,
                )
                self.assertEqual(proc.returncode, 0, proc.stdout)
                self.assertIn("[ok] loaded 1 custom detector(s)", proc.stdout)
                self.assertIn(f"=== Running {PATTERN} ===", proc.stdout)
                self.assertIn(f"[done] total hits: {expected_hits}", proc.stdout)

    def test_run_custom_sees_w68_sibling_detector_on_donation_fixture(self) -> None:
        python = _python_with_slither()
        if python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        cases = (
            (VULN, True),
            (W68_VULN, True),
            (CLEAN, False),
            (GUARDED_CLEAN, False),
            (W68_CLEAN, False),
        )
        for path, should_hit in cases:
            with self.subTest(path=path.name):
                proc = subprocess.run(
                    [
                        python,
                        str(RUN_CUSTOM),
                        "--tier=ALL",
                        str(path),
                        W68_PATTERN,
                    ],
                    cwd=ROOT,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=120,
                )
                self.assertEqual(proc.returncode, 0, proc.stdout)
                self.assertIn("[ok] loaded 1 custom detector(s)", proc.stdout)
                self.assertIn(f"=== Running {W68_PATTERN} ===", proc.stdout)
                if should_hit:
                    self.assertRegex(proc.stdout, r"\[done\] total hits: [1-9][0-9]*")
                else:
                    self.assertIn("[done] total hits: 0", proc.stdout)


if __name__ == "__main__":
    unittest.main()
