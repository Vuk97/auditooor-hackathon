"""Smoke-fire regression for the public factory invalid pool config detector.

This is intentionally narrow: copy the paired fixtures into an isolated
scratch workspace, run the real Slither-backed batch detector path, and assert
that the vulnerable fixture matches while the clean fixture stays quiet.
"""

from __future__ import annotations

import os
import importlib.util
import io
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import yaml


REPO = Path(__file__).resolve().parents[2]
DETECTOR = "public-factory-invalid-pool-config-liveness-failure"
FIXTURE_VULN = REPO / "patterns" / "fixtures" / f"{DETECTOR}_vuln.sol"
FIXTURE_CLEAN = REPO / "patterns" / "fixtures" / f"{DETECTOR}_clean.sol"
RUN_CUSTOM = REPO / "detectors" / "run_custom.py"
PATTERN_YAML = REPO / "reference" / "patterns.dsl" / f"{DETECTOR}.yaml"
DETECTOR_PY = REPO / "detectors" / "wave17" / f"{DETECTOR.replace('-', '_')}.py"


def _python_with_slither() -> str | None:
    """Return a Python executable that can import slither-analyzer."""

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
                [
                    candidate,
                    "-c",
                    "import slither; import slither.detectors.abstract_detector",
                ],
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


def _load_pattern() -> dict:
    return yaml.safe_load(PATTERN_YAML.read_text(encoding="utf-8"))


def _load_pattern_compile():
    tool = REPO / "tools" / "pattern-compile.py"
    spec = importlib.util.spec_from_file_location("pattern_compile", tool)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _create_pool_source(path: Path) -> str:
    source = path.read_text(encoding="utf-8")
    start = source.index("    function createPool(")
    end = source.index("        emit PoolCreated(pool);", start)
    return source[start : source.index("\n    }", end) + len("\n    }")]


def _regex_value(predicate: dict, key: str) -> str | None:
    return predicate.get(key) if isinstance(predicate, dict) else None


class PublicFactoryInvalidPoolConfigGeneratedIntegrationTest(unittest.TestCase):
    def test_pattern_compile_round_trip_matches_generated_detector(self) -> None:
        """The YAML remains the source of truth for the checked-in detector."""

        compiler = _load_pattern_compile()
        with tempfile.TemporaryDirectory(prefix=".pattern_compile_public_factory_", dir=REPO) as tmp:
            out_dir = Path(tmp) / "wave17"
            with redirect_stdout(io.StringIO()):
                compiled = compiler.compile_pattern(
                    PATTERN_YAML,
                    out_dir,
                    strict_yaml_shapes=True,
                    strict_unsupported_keys=True,
                )

            self.assertTrue(compiled)
            generated = out_dir / DETECTOR_PY.name
            self.assertTrue(generated.is_file(), f"missing generated detector: {generated}")
            self.assertEqual(
                DETECTOR_PY.read_text(encoding="utf-8"),
                generated.read_text(encoding="utf-8"),
            )


class PublicFactoryInvalidPoolConfigFixtureShapeTest(unittest.TestCase):
    def test_vulnerable_fixture_satisfies_detector_shape_without_slither(self) -> None:
        """Hermetic guard: the vuln fixture still has the risky shape."""

        spec = _load_pattern()
        source = FIXTURE_VULN.read_text(encoding="utf-8")
        function_source = _create_pool_source(FIXTURE_VULN)

        precondition = _regex_value(spec["preconditions"][0], "contract.source_matches_regex")
        self.assertIsNotNone(precondition)
        self.assertRegex(source, precondition)

        for predicate in spec["match"]:
            contains = _regex_value(predicate, "function.body_contains_regex")
            if contains:
                self.assertRegex(function_source, contains)

            not_contains = _regex_value(predicate, "function.body_not_contains_regex")
            if not_contains:
                self.assertIsNone(
                    re.search(not_contains, function_source),
                    f"vuln fixture unexpectedly has suppressor regex: {not_contains}",
                )

    def test_non_reverting_amp_zero_branch_is_not_a_suppressor(self) -> None:
        """Regression: observing amp==0 is not validation unless it rejects."""

        spec = _load_pattern()
        function_source = _create_pool_source(FIXTURE_VULN)
        self.assertIn("if (amp == 0)", function_source)
        self.assertIn("effectiveSwapFeeBps = defaultSwapFeeBps;", function_source)

        suppressor_regexes = [
            value
            for predicate in spec["match"]
            if (value := _regex_value(predicate, "function.body_not_contains_regex"))
        ]
        for regex in suppressor_regexes:
            self.assertIsNone(
                re.search(regex, function_source),
                f"non-reverting branch unexpectedly suppresses detector: {regex}",
            )

    def test_clean_fixture_keeps_same_factory_shape_but_has_suppressors(self) -> None:
        """Hermetic guard: clean differs by validations, not by evading setup."""

        spec = _load_pattern()
        function_source = _create_pool_source(FIXTURE_CLEAN)

        contains_regexes = [
            value
            for predicate in spec["match"]
            if (value := _regex_value(predicate, "function.body_contains_regex"))
        ]
        suppressor_regexes = [
            value
            for predicate in spec["match"]
            if (value := _regex_value(predicate, "function.body_not_contains_regex"))
        ]

        self.assertEqual(len(contains_regexes), 2)
        self.assertEqual(len(suppressor_regexes), 2)
        for regex in contains_regexes:
            self.assertRegex(function_source, regex)
        for regex in suppressor_regexes:
            self.assertRegex(function_source, regex)


class PublicFactoryInvalidPoolConfigLivenessFailureSmokeTest(unittest.TestCase):
    def test_vuln_fixture_hits_and_clean_fixture_does_not(self) -> None:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest(
                "slither-analyzer is not importable by the tested Python "
                "interpreters; install it or set SLITHER_PYTHON to the "
                "interpreter used by the slither CLI"
            )

        self.assertTrue(FIXTURE_VULN.is_file(), f"missing fixture: {FIXTURE_VULN}")
        self.assertTrue(FIXTURE_CLEAN.is_file(), f"missing fixture: {FIXTURE_CLEAN}")

        with tempfile.TemporaryDirectory(prefix="public_factory_invalid_pool_") as tmp:
            scratch = Path(tmp)
            shutil.copy2(FIXTURE_VULN, scratch / FIXTURE_VULN.name)
            shutil.copy2(FIXTURE_CLEAN, scratch / FIXTURE_CLEAN.name)
            (scratch / "foundry.toml").write_text(
                '[profile.default]\nsrc = "."\nout = "out"\n',
                encoding="utf-8",
            )
            regression = scratch / "regression.tsv"
            regression.write_text(
                "\n".join(
                    [
                        f"vuln\t{DETECTOR}\t{FIXTURE_VULN.name}\t{DETECTOR}",
                        f"clean\t{DETECTOR}\t{FIXTURE_CLEAN.name}\t{DETECTOR} (clean)",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

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
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=120,
            )

        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn("Batch regression: 2/2 passed, 0 failed", proc.stdout)


if __name__ == "__main__":
    unittest.main()
