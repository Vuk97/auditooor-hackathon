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
PATTERN_COMPILE = ROOT / "tools" / "pattern-compile.py"
RUN_CUSTOM = ROOT / "detectors" / "run_custom.py"
SMOKE = ROOT / "detectors" / "fixtures" / "w68_zero_coverage" / "solidity_runtime_smoke.json"


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


class W68SolidityRuntimeWiringTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.compiler = _load_module(PATTERN_COMPILE, "pattern_compile")
        cls.smoke = json.loads(SMOKE.read_text(encoding="utf-8"))

    def test_smoke_manifest_lists_only_solidity_runtime_rows(self) -> None:
        self.assertEqual(self.smoke["status"], "passed_vulnerable_clean_smoke")
        self.assertEqual(self.smoke["backend"], "slither")
        self.assertEqual(self.smoke["generated_wave"], "wave68")

        patterns = {case["pattern"] for case in self.smoke["cases"]}
        self.assertEqual(len(patterns), 12)
        self.assertNotIn("w68-consensus-param-corruption-no-validate", patterns)
        self.assertNotIn("w68-ibc-rate-limit-bypass-packet-handler", patterns)
        self.assertNotIn("w68-subaccount-isolation-bypass-missing-owner-check", patterns)

        for case in self.smoke["cases"]:
            reference = ROOT / "reference" / "patterns.dsl" / f"{case['pattern']}.yaml"
            spec = yaml.safe_load(reference.read_text(encoding="utf-8"))
            self.assertNotEqual(str(spec.get("backend", "")).lower(), "cosmos")
            self.assertTrue((ROOT / case["positive_fixture"]).is_file())
            self.assertTrue((ROOT / case["clean_fixture"]).is_file())
            self.assertEqual(case["positive_hits"], 1)
            self.assertEqual(case["clean_hits"], 0)

    def test_patterns_compile_under_strict_guards(self) -> None:
        for case in self.smoke["cases"]:
            with self.subTest(pattern=case["pattern"]):
                reference = ROOT / "reference" / "patterns.dsl" / f"{case['pattern']}.yaml"
                with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
                    ok = self.compiler.compile_pattern(
                        reference,
                        Path(tmp) / "wave68",
                        strict_yaml_shapes=True,
                        strict_unsupported_keys=True,
                    )
                self.assertTrue(ok)

    def test_generated_wave68_modules_are_checked_in(self) -> None:
        for case in self.smoke["cases"]:
            pattern = case["pattern"]
            with self.subTest(pattern=pattern):
                module_path = ROOT / "detectors" / "wave68" / f"{pattern.replace('-', '_')}.py"
                self.assertTrue(module_path.is_file())
                source = module_path.read_text(encoding="utf-8")
                self.assertIn(f'ARGUMENT = "{pattern}"', source)

    def test_run_custom_sees_generated_wave68_detectors(self) -> None:
        python = _python_with_slither()
        if python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        for case in self.smoke["cases"]:
            pattern = case["pattern"]
            for fixture_key, expected_hits in (
                ("positive_fixture", case["positive_hits"]),
                ("clean_fixture", case["clean_hits"]),
            ):
                with self.subTest(pattern=pattern, fixture=fixture_key):
                    proc = subprocess.run(
                        [
                            python,
                            str(RUN_CUSTOM),
                            "--tier=ALL",
                            str(ROOT / case[fixture_key]),
                            pattern,
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
                    self.assertIn(f"=== Running {pattern} ===", proc.stdout)
                    self.assertIn(f"[done] total hits: {expected_hits}", proc.stdout)


if __name__ == "__main__":
    unittest.main()
