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
PATTERN = "bridge-fiat-shamir-caller-omits-validator-set-identity"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "bridge_fiat_shamir_caller_omits_validator_set_identity"
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


class BridgeFiatShamirCallerRecallSlice43Test(unittest.TestCase):
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

    def test_taxonomy_maps_to_bridge_proof_domain_bypass(self) -> None:
        spec = yaml.safe_load(REFERENCE.read_text(encoding="utf-8"))
        self.assertEqual(
            self.classifier.classify_pattern(spec, PATTERN)["attack_class"],
            "bridge-proof-domain-bypass",
        )
        self.assertEqual(
            self.backtest.derive_attack_class(PATTERN, spec.get("tags")),
            "bridge-proof-domain-bypass",
        )

    def test_fixture_pair_models_caller_level_positive_and_identity_bound_clean(self) -> None:
        positive = (FIXTURE_DIR / "positive.sol").read_text(encoding="utf-8")
        clean = (FIXTURE_DIR / "clean.sol").read_text(encoding="utf-8")

        self.assertIn("createFiatShamirHash(commitmentHash, bitFieldHash, validatorSetRoot)", positive)
        self.assertIn("uint256 validatorSetLength", positive)
        self.assertNotIn("FIAT_SHAMIR_DOMAIN_ID", positive)

        self.assertIn("FIAT_SHAMIR_DOMAIN_ID", clean)
        self.assertIn("bytes32(uint256(vset.id))", clean)
        self.assertIn("bytes32(uint256(vset.length))", clean)
        self.assertIn("createFiatShamirHash(commitmentHash, bitFieldHash, vset)", clean)

    def test_smoke_record_captures_positive_and_clean_counts(self) -> None:
        payload = json.loads((FIXTURE_DIR / "smoke.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["schema"], "auditooor.canonical_detector_fixture_smoke.v1")
        self.assertEqual(payload["status"], "passed_vulnerable_clean_smoke")
        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)

    def test_generated_wave70_detector_is_checked_in(self) -> None:
        module_path = ROOT / "detectors" / "wave70" / "bridge_fiat_shamir_caller_omits_validator_set_identity.py"
        self.assertTrue(module_path.is_file())
        source = module_path.read_text(encoding="utf-8")
        self.assertIn(f'ARGUMENT = "{PATTERN}"', source)
        self.assertIn("_INCLUDE_LEAF_HELPERS = True", source)

    def test_direct_pattern_runner_positive_fires_and_clean_stays_quiet(self) -> None:
        if _python_with_slither() is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        engine = self.backtest._import_engine()
        spec = yaml.safe_load(REFERENCE.read_text(encoding="utf-8"))

        positive_hits, positive_error = self.backtest.run_pattern_on_file(
            spec,
            FIXTURE_DIR / "positive.sol",
            engine,
        )
        self.assertIsNone(positive_error)
        self.assertEqual(positive_hits, 1)

        clean_hits, clean_error = self.backtest.run_pattern_on_file(
            spec,
            FIXTURE_DIR / "clean.sol",
            engine,
        )
        self.assertIsNone(clean_error)
        self.assertEqual(clean_hits, 0)

    def test_run_custom_sees_generated_detector(self) -> None:
        python = _python_with_slither()
        if python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        for fixture_name, expected_hits in (("positive.sol", 1), ("clean.sol", 0)):
            with self.subTest(fixture=fixture_name):
                proc = subprocess.run(
                    [
                        python,
                        str(RUN_CUSTOM),
                        "--tier=ALL",
                        str(FIXTURE_DIR / fixture_name),
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
