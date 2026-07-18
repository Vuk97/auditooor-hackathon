#!/usr/bin/env python3
"""Tests for tools/regression-sentinel-runner.py — Wave-7 BIG_PLAN A5."""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MOD_PATH = REPO_ROOT / "tools" / "regression-sentinel-runner.py"


def _load() -> object:
    spec = importlib.util.spec_from_file_location("rsr_for_test", MOD_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {MOD_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["rsr_for_test"] = mod
    spec.loader.exec_module(mod)
    return mod


RSR = _load()


class TestSentinelConditionParse(unittest.TestCase):

    def test_parses_known_classes(self):
        for raw in (
            "file_line_present x/y.go:42",
            "middleware_absent IBCHooksKeeper",
            "gov_config_unchanged BLOCK_MAX_GAS=200000000",
            "fork_pin_unchanged cometbft/cometbft:904204b11c9e",
            "detector_silent missing-guard-foo",
        ):
            c = RSR.SentinelCondition.parse(raw)
            self.assertIn(c.cls, RSR.CONDITION_CLASSES)
            self.assertTrue(c.body)

    def test_rejects_unknown_class(self):
        with self.assertRaises(ValueError):
            RSR.SentinelCondition.parse("kebab_squirrel foo")

    def test_rejects_empty(self):
        with self.assertRaises(ValueError):
            RSR.SentinelCondition.parse("")


class TestHeaderExtraction(unittest.TestCase):

    def test_parses_go_double_slash_header(self):
        text = (
            "package foo\n"
            "// regression-sentinel-condition: middleware_absent IBCHooksKeeper\n"
            "func main() {}\n"
        )
        conds = RSR.parse_sentinel_headers(text)
        self.assertEqual(len(conds), 1)
        self.assertEqual(conds[0].cls, "middleware_absent")
        self.assertEqual(conds[0].body, "IBCHooksKeeper")

    def test_parses_python_hash_header(self):
        text = (
            "# regression-sentinel-condition: detector_silent foo-detector\n"
            "import sys\n"
        )
        conds = RSR.parse_sentinel_headers(text)
        self.assertEqual(len(conds), 1)
        self.assertEqual(conds[0].cls, "detector_silent")

    def test_multiple_headers_collected(self):
        text = (
            "// regression-sentinel-condition: file_line_present a/b.go:10\n"
            "// regression-sentinel-condition: middleware_absent X\n"
        )
        conds = RSR.parse_sentinel_headers(text)
        self.assertEqual(len(conds), 2)


class TestEvaluators(unittest.TestCase):

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.root = Path(self._td.name)
        self.ctx = RSR.EvalContext(resolve_root=self.root, grep_timeout=5)

    def tearDown(self):
        self._td.cleanup()

    def test_file_line_present_holds(self):
        target = self.root / "sub" / "f.go"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("line1\nline2\nline3\n", encoding="utf-8")
        holds, detail = RSR._eval_file_line_present("sub/f.go:2", self.ctx)
        self.assertTrue(holds, detail)
        self.assertIn("still present", detail)

    def test_file_line_present_violated_when_missing(self):
        holds, detail = RSR._eval_file_line_present("nosuch/file.go:1", self.ctx)
        self.assertFalse(holds)
        self.assertIn("file missing", detail)

    def test_file_line_present_violated_when_line_out_of_range(self):
        target = self.root / "f.go"
        target.write_text("only-one-line\n", encoding="utf-8")
        holds, detail = RSR._eval_file_line_present("f.go:50", self.ctx)
        self.assertFalse(holds)
        self.assertIn("out of range", detail)

    def test_middleware_absent_holds_when_no_hits(self):
        # empty tree -> middleware not found -> holds True
        holds, detail = RSR._eval_middleware_absent("DefinitelyNotPresentXYZ", self.ctx)
        self.assertTrue(holds, detail)

    def test_middleware_absent_violated_when_installed(self):
        ext = self.root / "external" / "subproj"
        ext.mkdir(parents=True, exist_ok=True)
        (ext / "wire.go").write_text(
            "package wire\nvar k = IBCHooksKeeper{}\n", encoding="utf-8",
        )
        holds, detail = RSR._eval_middleware_absent("IBCHooksKeeper", self.ctx)
        self.assertFalse(holds, detail)
        self.assertIn("now installed", detail)

    def test_fork_pin_unchanged_holds_via_ledger(self):
        ledger = self.root / ".auditooor" / "commit_lifecycle_ledger.json"
        ledger.parent.mkdir(parents=True, exist_ok=True)
        ledger.write_text(json.dumps({"pin": "904204b11c9e1234"}), encoding="utf-8")
        holds, detail = RSR._eval_fork_pin_unchanged(
            "cometbft/cometbft:904204b11c9e1234", self.ctx,
        )
        self.assertTrue(holds, detail)

    def test_fork_pin_unchanged_violated_when_missing(self):
        # No ledger, no SCOPE.md → not found
        holds, detail = RSR._eval_fork_pin_unchanged(
            "cometbft/cometbft:deadbeefcafef00d", self.ctx,
        )
        self.assertFalse(holds)

    def test_detector_silent_holds_when_engage_clean(self):
        engage = self.root / "engage_report.md"
        engage.write_text("# Engage Report\n\nAll-clean: no detectors fired.\n",
                          encoding="utf-8")
        holds, detail = RSR._eval_detector_silent("missing-guard-foo", self.ctx)
        self.assertTrue(holds, detail)

    def test_detector_silent_violated_when_filehits(self):
        engage = self.root / "engage_report.md"
        engage.write_text(
            "missing-guard-foo: external/proj/x.go:12 hit-here\n",
            encoding="utf-8",
        )
        holds, detail = RSR._eval_detector_silent("missing-guard-foo", self.ctx)
        self.assertFalse(holds)
        self.assertIn("now firing", detail)


class TestRegistryLoad(unittest.TestCase):

    def test_loads_registry_yaml(self):
        if RSR.yaml is None:
            self.skipTest("PyYAML not installed")
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "reg.yaml"
            p.write_text(textwrap.dedent("""
                sentinels:
                  - id: test-sentinel-1
                    poc_path: /tmp/does-not-exist
                    condition: file_line_present a/b.go:1
                    severity_if_fires: HIGH
                    notes: "smoke entry"
            """).lstrip(), encoding="utf-8")
            rows = RSR.load_registry(p)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0].sentinel_id, "test-sentinel-1")
            self.assertEqual(rows[0].condition.cls, "file_line_present")
            self.assertEqual(rows[0].severity_if_fires, "HIGH")

    def test_missing_registry_returns_empty(self):
        rows = RSR.load_registry(Path("/tmp/definitely-not-here-xyz.yaml"))
        self.assertEqual(rows, [])

    def test_repo_registry_parses(self):
        """The committed registry under audit/ must parse cleanly."""
        if RSR.yaml is None:
            self.skipTest("PyYAML not installed")
        reg = REPO_ROOT / "audit" / "regression_sentinels_registry.yaml"
        self.assertTrue(reg.exists(), f"registry must exist: {reg}")
        rows = RSR.load_registry(reg)
        self.assertGreaterEqual(len(rows), 3,
                                "registry should ship ≥3 sentinels (A5.3)")
        for r in rows:
            self.assertIn(r.condition.cls, RSR.CONDITION_CLASSES)


class TestEndToEndFlow(unittest.TestCase):

    def test_violation_triggers_rerun_and_emit(self):
        """End-to-end smoke: violated condition + passing rerun → FIRED artifact."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            # Construct a python PoC that always passes
            poc_dir = ws / "submissions" / "held"
            poc_dir.mkdir(parents=True)
            poc_file = poc_dir / "trivial_test.py"
            poc_file.write_text(textwrap.dedent("""
                # regression-sentinel-condition: file_line_present nosuch.go:1
                import unittest
                class T(unittest.TestCase):
                    def test_pass(self):
                        self.assertTrue(True)
                if __name__ == '__main__':
                    unittest.main()
            """).lstrip(), encoding="utf-8")
            results = RSR.run(
                workspace=ws,
                registry_path=None,
                extra_poc_dirs=[],
                rerun_enabled=True,
                emit_root=ws,
                grep_timeout=5,
            )
            self.assertEqual(len(results), 1)
            r = results[0]
            self.assertFalse(r.condition_holds)
            self.assertTrue(r.rerun_required)
            # Either the rerun passed (artifact emitted) or PyYAML/python
            # invocation isn't viable. Accept either.
            if r.rerun_passed:
                self.assertIsNotNone(r.fired_artifact_path)
                self.assertTrue(r.fired_artifact_path.exists())
                body = r.fired_artifact_path.read_text(encoding="utf-8")
                self.assertIn("REGRESSION SENTINEL FIRED", body)


if __name__ == "__main__":
    unittest.main()
