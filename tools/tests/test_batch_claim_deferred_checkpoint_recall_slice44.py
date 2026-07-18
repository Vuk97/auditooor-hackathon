from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
PATTERN = "batch-claim-deferred-checkpoint-duplicate-input"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "batch_claim_deferred_checkpoint_duplicate_input"
DUPLICATE_ENTRIES_FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "duplicate_entries_in_batch_claim"
PATTERN_COMPILE = ROOT / "tools" / "pattern-compile.py"
CLASSIFIER_TOOL = ROOT / "tools" / "audit" / "detector-class-map-builder.py"
BACKTEST_TOOL = ROOT / "tools" / "audit" / "detector-catch-rate-backtest.py"
RUN_CUSTOM = ROOT / "detectors" / "run_custom.py"


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


class BatchClaimDeferredCheckpointRecallSlice44Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.compiler = _load_module(PATTERN_COMPILE, "pattern_compile")
        cls.classifier = _load_module(CLASSIFIER_TOOL, "detector_class_map_builder")
        cls.backtest = _load_module(BACKTEST_TOOL, "detector_catch_rate_backtest")

    def test_pattern_compiles_under_strict_guards(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            ok = self.compiler.compile_pattern(
                REFERENCE,
                Path(tmp) / "wave70",
                strict_yaml_shapes=True,
                strict_unsupported_keys=True,
            )
        self.assertTrue(ok)

    def test_taxonomy_maps_to_state_change_between_check_and_use(self) -> None:
        spec = yaml.safe_load(REFERENCE.read_text(encoding="utf-8"))
        self.assertEqual(
            self.classifier.classify_pattern(spec, PATTERN)["attack_class"],
            "state-change-between-check-and-use",
        )
        self.assertEqual(
            self.backtest.derive_attack_class(PATTERN, spec.get("tags")),
            "state-change-between-check-and-use",
        )

    def test_fixture_pair_models_duplicate_batch_claim_and_unique_clean(self) -> None:
        positive = (FIXTURE_DIR / "positive.sol").read_text(encoding="utf-8")
        clean = (FIXTURE_DIR / "clean.sol").read_text(encoding="utf-8")

        self.assertIn("function batchClaim(address[] calldata tokenList)", positive)
        self.assertIn("_claim(tokenList[i], msg.sender)", positive)
        self.assertIn("syncCheckpoint", positive)
        self.assertNotIn("_requireUnique(tokenList, i)", positive)

        self.assertIn("_requireUnique(tokenList, i)", clean)
        self.assertIn("lastCheckpoint[user][token] = cumulative", clean)

    def test_smoke_record_captures_fixture_and_cross_fixture_counts(self) -> None:
        payload = json.loads((FIXTURE_DIR / "smoke.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["schema"], "auditooor.canonical_detector_fixture_smoke.v1")
        self.assertEqual(payload["status"], "passed_vulnerable_clean_smoke")
        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)
        self.assertEqual(payload["cross_positive_duplicate_entries_hits"], 1)
        self.assertEqual(payload["cross_clean_duplicate_entries_hits"], 0)

    def test_generated_wave70_detector_is_checked_in(self) -> None:
        module_path = ROOT / "detectors" / "wave70" / "batch_claim_deferred_checkpoint_duplicate_input.py"
        self.assertTrue(module_path.is_file())
        source = module_path.read_text(encoding="utf-8")
        self.assertIn(f'ARGUMENT = "{PATTERN}"', source)
        self.assertIn("_INCLUDE_LEAF_HELPERS = True", source)

    def test_run_custom_sees_fixture_and_prior_recall_sample(self) -> None:
        python = _python_with_slither()
        if python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        cases = [
            (FIXTURE_DIR / "positive.sol", 1),
            (FIXTURE_DIR / "clean.sol", 0),
            (DUPLICATE_ENTRIES_FIXTURE_DIR / "positive.sol", 1),
            (DUPLICATE_ENTRIES_FIXTURE_DIR / "clean.sol", 0),
        ]
        for path, expected_hits in cases:
            with self.subTest(path=path.name, expected_hits=expected_hits):
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


if __name__ == "__main__":
    unittest.main()
