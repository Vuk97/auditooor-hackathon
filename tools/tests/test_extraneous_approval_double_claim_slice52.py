from __future__ import annotations

import importlib.util
import os
import py_compile
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
PATTERNS = [
    "extraneous-approval-in-withdrawal-double-claim",
    "withdrawal-approve-transfer-same-recipient",
]
REFERENCE_DIR = ROOT / "reference" / "patterns.dsl"
EXTRANEOUS_VULN = ROOT / "patterns" / "fixtures" / "extraneous-approval-in-withdrawal-double-claim_vuln.sol"
APPROVE_VULN = ROOT / "patterns" / "fixtures" / "withdrawal-approve-transfer-same-recipient_vuln.sol"
APPROVE_CLEAN = ROOT / "patterns" / "fixtures" / "withdrawal-approve-transfer-same-recipient_clean.sol"
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


class ExtraneousApprovalDoubleClaimSlice52Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.compiler = _load_module(PATTERN_COMPILE, "pattern_compile_slice52")
        cls.classifier = _load_module(CLASSIFIER_TOOL, "detector_class_map_builder_slice52")
        cls.backtest = _load_module(BACKTEST_TOOL, "detector_catch_rate_backtest_slice52")

    def _spec(self, slug: str):
        return yaml.safe_load((REFERENCE_DIR / f"{slug}.yaml").read_text(encoding="utf-8"))

    def test_metadata_and_taxonomy_are_fund_loss(self) -> None:
        shared_map = yaml.safe_load(
            (ROOT / "reference" / "detector_class_map_complete.yaml").read_text(encoding="utf-8")
        )

        for slug in PATTERNS:
            with self.subTest(slug=slug):
                spec = self._spec(slug)
                self.assertIn("fund-loss-via-arithmetic", spec.get("tags", []))
                self.assertEqual(
                    self.classifier.classify_pattern(spec, slug)["attack_class"],
                    "fund-loss-via-arithmetic",
                )
                self.assertEqual(
                    self.backtest.derive_attack_class(slug, spec.get("tags")),
                    "fund-loss-via-arithmetic",
                )
                row = shared_map["mappings"][slug]
                self.assertEqual(row["attack_class"], "fund-loss-via-arithmetic")
                self.assertEqual(row["evidence"], "tags")

    def test_patterns_compile_under_strict_guards(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            out = Path(tmp) / "wave18"
            for slug in PATTERNS:
                with self.subTest(slug=slug):
                    ok = self.compiler.compile_pattern(
                        REFERENCE_DIR / f"{slug}.yaml",
                        out,
                        strict_yaml_shapes=True,
                        strict_unsupported_keys=True,
                    )
                    self.assertTrue(ok)

    def test_direct_pattern_runner_hits_sibling_samples_and_controls(self) -> None:
        if _python_with_slither() is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        engine = self.backtest._import_engine()
        extraneous = self._spec("extraneous-approval-in-withdrawal-double-claim")
        approve_unspent = self._spec("withdrawal-approve-transfer-same-recipient")

        for spec, path in (
            (extraneous, EXTRANEOUS_VULN),
            (extraneous, APPROVE_VULN),
            (approve_unspent, EXTRANEOUS_VULN),
            (approve_unspent, APPROVE_VULN),
        ):
            with self.subTest(pattern=spec["pattern"], path=path.name):
                hits, err = self.backtest.run_pattern_on_file(spec, path, engine)
                self.assertIsNone(err)
                self.assertGreaterEqual(hits, 1)

        for spec in (extraneous, approve_unspent):
            with self.subTest(pattern=spec["pattern"], path=APPROVE_CLEAN.name):
                hits, err = self.backtest.run_pattern_on_file(spec, APPROVE_CLEAN, engine)
                self.assertIsNone(err)
                self.assertEqual(hits, 0)

    def test_run_custom_sees_generated_detector_on_positive_and_clean(self) -> None:
        python = _python_with_slither()
        if python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        for slug in PATTERNS:
            for path, expected_hits in ((APPROVE_VULN, True), (APPROVE_CLEAN, False)):
                with self.subTest(slug=slug, path=path.name):
                    proc = subprocess.run(
                        [python, str(RUN_CUSTOM), "--tier=ALL", str(path), slug],
                        cwd=ROOT,
                        env=env,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        timeout=120,
                    )
                    self.assertEqual(proc.returncode, 0, proc.stdout)
                    self.assertIn("[ok] loaded 1 custom detector(s)", proc.stdout)
                    self.assertIn(f"=== Running {slug} ===", proc.stdout)
                    if expected_hits:
                        self.assertRegex(proc.stdout, r"\[done\] total hits: [1-9][0-9]*")
                    else:
                        self.assertIn("[done] total hits: 0", proc.stdout)

    def test_generated_detectors_are_valid_python(self) -> None:
        for slug in PATTERNS:
            stem = slug.replace("-", "_")
            py_compile.compile(ROOT / "detectors" / "wave17" / f"{stem}.py", doraise=True)


if __name__ == "__main__":
    unittest.main()
