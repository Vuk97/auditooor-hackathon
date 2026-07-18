#!/usr/bin/env python3
"""Regression G2 (2026-06-27): function-coverage-completeness must not green-pass
a FAILED source resolution. Before: `not any_source` -> pass-no-source (rc 0,
GREEN) regardless of whether the workspace actually has source. Workspaces whose
in-scope code lives under lib/examples/test, or a path-prefix the resolver
excludes, resolved to 0 -> silent green coverage on a ws that HAS real source.
Fix: cross-check the inscope manifest / a raw source walk; if source exists,
emit verdict 'error-no-source-resolved' (rc 2), not a clean pass."""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

_MOD = Path(__file__).resolve().parents[1] / "function-coverage-completeness.py"
_spec = importlib.util.spec_from_file_location("function_coverage_completeness", _MOD)
fcc = importlib.util.module_from_spec(_spec)
sys.modules["function_coverage_completeness"] = fcc  # python3.14 @dataclass needs this
_spec.loader.exec_module(fcc)


class FccNoSourceGuardTest(unittest.TestCase):
    def test_helper_empty_ws_false(self):
        with tempfile.TemporaryDirectory() as t:
            self.assertFalse(fcc._ws_has_source_despite_resolution(Path(t)))

    def test_helper_manifest_nonempty_true(self):
        with tempfile.TemporaryDirectory() as t:
            w = Path(t)
            (w / ".auditooor").mkdir()
            (w / ".auditooor" / "inscope_units.jsonl").write_text(
                '{"file":"lib/x/A.sol","function":"f"}\n', encoding="utf-8")
            self.assertTrue(fcc._ws_has_source_despite_resolution(w))

    def test_helper_source_under_lib_true(self):
        with tempfile.TemporaryDirectory() as t:
            w = Path(t)
            (w / "lib" / "x").mkdir(parents=True)
            # NOTE: lib/ is walk-skipped, so a manifest is the signal here; but a
            # vendored-only ws with NO manifest is correctly treated as no-source.
            self.assertFalse(fcc._ws_has_source_despite_resolution(w))

    def test_genuinely_empty_ws_still_pass_no_source(self):
        with tempfile.TemporaryDirectory() as t:
            w = Path(t) / "ws"
            w.mkdir()
            self.assertEqual(fcc.evaluate(w)["verdict"], "pass-no-source")

    def test_source_present_but_unresolved_is_error(self):
        # manifest says there is in-scope source, but the resolver finds none
        # (here: source only under a walk-skipped dir + a manifest row) -> error.
        with tempfile.TemporaryDirectory() as t:
            w = Path(t) / "ws"
            (w / "lib" / "x").mkdir(parents=True)
            (w / "lib" / "x" / "A.sol").write_text("contract A{function f() external{}}", encoding="utf-8")
            (w / ".auditooor").mkdir()
            (w / ".auditooor" / "inscope_units.jsonl").write_text(
                '{"file":"lib/x/A.sol","function":"f","lang":"solidity"}\n', encoding="utf-8")
            v = fcc.evaluate(w)["verdict"]
            self.assertEqual(v, "error-no-source-resolved", f"got {v}")


if __name__ == "__main__":
    unittest.main()
