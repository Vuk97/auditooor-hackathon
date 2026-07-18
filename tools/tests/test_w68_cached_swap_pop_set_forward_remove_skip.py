from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUN_CUSTOM = ROOT / "detectors" / "run_custom.py"
PATTERN = "w68-cached-swap-pop-set-forward-remove-skip"
POSITIVE = ROOT / "detectors" / "fixtures" / "w68_zero_coverage" / "cached_swap_pop_set_forward_remove_positive.sol"
CLEAN = ROOT / "detectors" / "fixtures" / "w68_zero_coverage" / "cached_swap_pop_set_forward_remove_clean.sol"
ORIGIN_POSITIVE = ROOT / "detectors" / "fixtures" / "w68_zero_coverage" / "loop_invariant_bypass_positive.sol"
ORIGIN_CLEAN = ROOT / "detectors" / "fixtures" / "w68_zero_coverage" / "loop_invariant_bypass_clean.sol"
DETECTOR = ROOT / "detectors" / "wave68" / "w68_cached_swap_pop_set_forward_remove_skip.py"
CLASS_MAP = ROOT / "reference" / "detector_to_attack_classes_map.yaml"
BACKTEST = ROOT / "tools" / "audit" / "detector-catch-rate-backtest.py"


def _load_backtest_module():
    spec = importlib.util.spec_from_file_location("detector_catch_rate_backtest", BACKTEST)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _python_with_slither() -> str | None:
    candidates = [
        os.environ.get("SLITHER_PYTHON"),
        sys.executable,
        "/opt/homebrew/opt/python@3.14/bin/python3.14",
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


class W68CachedSwapPopSetForwardRemoveSkipTest(unittest.TestCase):
    def _run_hits(self, fixture: Path, expected_hits: int) -> None:
        python = _python_with_slither()
        if python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        self.assertTrue(DETECTOR.is_file())

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"

        proc = subprocess.run(
            [
                python,
                str(RUN_CUSTOM),
                "--tier=ALL",
                str(fixture),
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

    def test_cached_swap_pop_positive_fires_and_clean_is_silent(self) -> None:
        for fixture, expected_hits in ((POSITIVE, 1), (CLEAN, 0)):
            with self.subTest(fixture=fixture.name):
                self._run_hits(fixture, expected_hits)

    def test_loop_invariant_origin_fixture_now_fires_and_clean_is_silent(self) -> None:
        for fixture, expected_hits in ((ORIGIN_POSITIVE, 1), (ORIGIN_CLEAN, 0)):
            with self.subTest(fixture=fixture.name):
                self._run_hits(fixture, expected_hits)

    def test_attack_class_map_includes_loop_invariant_bypass_for_detector(self) -> None:
        class_map_text = CLASS_MAP.read_text(encoding="utf-8")
        self.assertIn("w68-cached-swap-pop-set-forward-remove-skip:", class_map_text)
        self.assertIn("loop-invariant-bypass", class_map_text)

    def test_runtime_attack_class_derivation_covers_both_sample_classes(self) -> None:
        backtest = _load_backtest_module()

        self.assertEqual(
            backtest.derive_attack_class(
                PATTERN,
                ["missing-last-element-validation", "loop-invariant-bypass"],
            ),
            "missing-last-element-validation",
        )
        self.assertEqual(
            backtest.derive_attack_classes(
                PATTERN,
                ["missing-last-element-validation", "loop-invariant-bypass"],
            ),
            {"missing-last-element-validation", "loop-invariant-bypass"},
        )
        self.assertEqual(
            backtest.derive_attack_class(
                "w68-loop-invariant-bypass-off-by-one",
                ["loop-invariant-bypass"],
            ),
            "loop-invariant-bypass",
        )


if __name__ == "__main__":
    unittest.main()
