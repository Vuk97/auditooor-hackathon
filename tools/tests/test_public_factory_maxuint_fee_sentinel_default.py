"""Focused regression for the max-uint fee sentinel input-validation lift."""

from __future__ import annotations

import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml


REPO = Path(__file__).resolve().parents[2]
PATTERN = REPO / "reference" / "patterns.dsl" / "public-factory-maxuint-fee-sentinel-default.yaml"
DETECTOR = REPO / "detectors" / "wave18" / "public_factory_maxuint_fee_sentinel_default.py"
FIXTURE_DIR = REPO / "detectors" / "fixtures" / "public_factory_maxuint_fee_sentinel_default"
FIXTURE_POSITIVE = FIXTURE_DIR / "positive.sol"
FIXTURE_CLEAN = FIXTURE_DIR / "clean.sol"
RUN_CUSTOM = REPO / "detectors" / "run_custom.py"
PATTERN_COMPILE = REPO / "tools" / "pattern-compile.py"


def _load_compiler():
    spec = importlib.util.spec_from_file_location("pattern_compile", PATTERN_COMPILE)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _pattern_spec() -> dict:
    return yaml.safe_load(PATTERN.read_text(encoding="utf-8"))


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
                cwd=REPO,
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


class PublicFactoryMaxuintFeeSentinelDefaultTest(unittest.TestCase):
    def test_pattern_compiles_under_strict_guards(self) -> None:
        compiler = _load_compiler()
        with tempfile.TemporaryDirectory(dir=REPO) as tmp:
            wave = Path(tmp) / "wave18"
            ok = compiler.compile_pattern(
                PATTERN,
                wave,
                strict_yaml_shapes=True,
                strict_unsupported_keys=True,
            )

            self.assertTrue(ok)
            emitted = (wave / "public_factory_maxuint_fee_sentinel_default.py").read_text(
                encoding="utf-8"
            )
            self.assertIn('ARGUMENT = "public-factory-maxuint-fee-sentinel-default"', emitted)
            self.assertIn("CONFIDENCE = DetectorClassification.MEDIUM", emitted)

    def test_fixture_pair_matches_pattern_shape_without_slither(self) -> None:
        spec = _pattern_spec()
        positive = FIXTURE_POSITIVE.read_text(encoding="utf-8")
        clean = FIXTURE_CLEAN.read_text(encoding="utf-8")

        self.assertTrue(FIXTURE_POSITIVE.is_file(), f"missing fixture: {FIXTURE_POSITIVE}")
        self.assertTrue(FIXTURE_CLEAN.is_file(), f"missing fixture: {FIXTURE_CLEAN}")
        for predicate in spec["match"]:
            if contains := predicate.get("function.body_contains_regex"):
                self.assertRegex(positive, re.compile(contains, re.IGNORECASE))
                self.assertRegex(clean, re.compile(contains, re.IGNORECASE))

            if not_contains := predicate.get("function.body_not_contains_regex"):
                self.assertIsNone(
                    re.search(not_contains, positive, re.IGNORECASE),
                    f"positive fixture unexpectedly has suppressor regex: {not_contains}",
                )
                self.assertIsNotNone(
                    re.search(not_contains, clean, re.IGNORECASE),
                    f"clean fixture should carry a suppressor regex: {not_contains}",
                )

    def test_positive_hits_and_clean_does_not_under_run_custom(self) -> None:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest(
                "slither-analyzer is not importable by the tested Python interpreters; "
                "install it or set SLITHER_PYTHON"
            )

        self.assertTrue(DETECTOR.is_file(), f"missing detector: {DETECTOR}")
        self.assertTrue(FIXTURE_POSITIVE.is_file(), f"missing fixture: {FIXTURE_POSITIVE}")
        self.assertTrue(FIXTURE_CLEAN.is_file(), f"missing fixture: {FIXTURE_CLEAN}")

        with tempfile.TemporaryDirectory(prefix="public_factory_maxuint_fee_", dir=REPO) as tmp:
            scratch = Path(tmp)
            shutil.copy2(FIXTURE_POSITIVE, scratch / FIXTURE_POSITIVE.name)
            shutil.copy2(FIXTURE_CLEAN, scratch / FIXTURE_CLEAN.name)
            (scratch / "foundry.toml").write_text(
                '[profile.default]\nsrc = "."\nout = "out"\n',
                encoding="utf-8",
            )
            regression = scratch / "regression.tsv"
            regression.write_text(
                "\n".join(
                    [
                        f"vuln\tpublic-factory-maxuint-fee-sentinel-default\t{FIXTURE_POSITIVE.name}\tpublic-factory-maxuint-fee-sentinel-default",
                        f"clean\tpublic-factory-maxuint-fee-sentinel-default\t{FIXTURE_CLEAN.name}\tpublic-factory-maxuint-fee-sentinel-default (clean)",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            env = os.environ.copy()
            env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
            env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
            proc = subprocess.run(
                [
                    slither_python,
                    str(RUN_CUSTOM),
                    "--batch",
                    str(scratch),
                    str(regression),
                    "--tier=ALL",
                ],
                cwd=REPO,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=120,
            )

        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn("Batch regression: 2/2 passed, 0 failed", proc.stdout)


if __name__ == "__main__":
    unittest.main()
