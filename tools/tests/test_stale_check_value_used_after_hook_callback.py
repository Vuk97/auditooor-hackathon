from __future__ import annotations

import importlib.util
import json
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
PATTERN = "stale-check-value-used-after-hook-callback"
DETECTOR = ROOT / "detectors" / "wave70" / "stale_check_value_used_after_hook_callback.py"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "stale_check_value_used_after_hook_callback"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
SMOKE = FIXTURE_DIR / "smoke.json"
PATTERN_COMPILE = ROOT / "tools" / "pattern-compile.py"
CLASSIFIER_TOOL = ROOT / "tools" / "audit" / "detector-class-map-builder.py"
BACKTEST_TOOL = ROOT / "tools" / "audit" / "detector-catch-rate-backtest.py"
CLASS_MAP = ROOT / "reference" / "detector_class_map_complete.yaml"


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


class StaleCheckValueUsedAfterHookCallbackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.compiler = _load_module(PATTERN_COMPILE, "pattern_compile")
        cls.classifier = _load_module(CLASSIFIER_TOOL, "detector_class_map_builder")
        cls.backtest = _load_module(BACKTEST_TOOL, "detector_catch_rate_backtest")

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
        self.assertNotIn("No custom detectors found", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_reference_pattern_compiles_and_maps_to_state_change_class(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            ok = self.compiler.compile_pattern(
                REFERENCE,
                Path(tmp) / "wave70",
                strict_yaml_shapes=True,
                strict_unsupported_keys=True,
            )
        self.assertTrue(ok)

        spec = yaml.safe_load(REFERENCE.read_text(encoding="utf-8"))
        class_map = yaml.safe_load(CLASS_MAP.read_text(encoding="utf-8"))
        row = class_map["mappings"][PATTERN]
        self.assertEqual(row["attack_class"], "state-change-between-check-and-use")
        self.assertEqual(row["attack_class_aliases"], ["callback-hook-exploit"])
        self.assertEqual(
            self.classifier.classify_pattern(spec, PATTERN)["attack_class"],
            "callback-hook-exploit",
        )
        self.assertEqual(
            self.backtest.derive_attack_class(PATTERN, spec.get("tags")),
            "state-change-between-check-and-use",
        )

    def test_detector_and_fixtures_pin_the_stale_cache_shape(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        reference_text = REFERENCE.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn(f'WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/{PATTERN}.yaml"', detector_text)
        self.assertIn(f"pattern: {PATTERN}", reference_text)
        self.assertIn("state-change-between-check-and-use", reference_text)
        self.assertIn("caches a checked balance", detector_text)
        self.assertIn("cachedBalance", positive_text)
        self.assertIn("hook.beforeWithdraw(msg.sender, amount);", positive_text)
        self.assertIn("balances[msg.sender] = cachedBalance - amount;", positive_text)
        self.assertIn("uint256 liveBalance = balances[msg.sender];", clean_text)
        self.assertIn("require(liveBalance >= amount, \"insufficient-after-hook\");", clean_text)
        self.assertNotIn("balances[msg.sender] = cachedBalance - amount;", clean_text)

        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["status"], "passed_vulnerable_clean_smoke")
        self.assertEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)
        self.assertEqual(payload["coverage_claim"], "detector_fixture_smoke_only")

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
