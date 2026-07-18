#!/usr/bin/env python3
# <!-- r36-rebuttal: lane MVC-MANUAL-LANG-INFER registered in commit message -->
"""NUVA 2026-06-30: register_manual_mvc hardcoded language="solidity", so a Go (or
Rust) cross-function mutant harness was mis-tagged language=solidity. Fix infers the
language from the CUT source / harness file extension via _EXT_LANG. Pins: .go->go,
.rs->rust, .sol->solidity, unknown->solidity (safe default).
"""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "mutation-verify-coverage.py"


def _load():
    spec = importlib.util.spec_from_file_location("mvc", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["mvc"] = m
    spec.loader.exec_module(m)
    return m


mvc = _load()


def _mk(name: str, body: str = "func TestX(){}\n") -> Path:
    d = Path(tempfile.mkdtemp(prefix="mvc_lang_"))
    p = d / name
    p.write_text(body, encoding="utf-8")
    return p


class ManualMvcLanguageInferenceTest(unittest.TestCase):
    def test_go_harness_tagged_go(self):
        h = _mk("reconcile_test.go")
        rec = mvc.register_manual_mvc(workspace=h.parent, harness_path=h,
                                      source_file=h.parent / "reconcile.go")
        self.assertEqual(rec["language"], "go")
        self.assertTrue(rec["mutation_verified"])

    def test_rust_harness_tagged_rust(self):
        h = _mk("lib_mutant.rs", "fn t(){}\n")
        rec = mvc.register_manual_mvc(workspace=h.parent, harness_path=h)
        self.assertEqual(rec["language"], "rust")

    def test_sol_harness_still_solidity(self):
        h = _mk("Foo_MutantVacuity.t.sol", "contract X{}\n")
        rec = mvc.register_manual_mvc(workspace=h.parent, harness_path=h)
        self.assertEqual(rec["language"], "solidity")

    def test_source_ext_preferred_over_harness(self):
        # harness is a generic shell cmd file but source is .go -> go
        h = _mk("run.sh", "go test ./...\n")
        rec = mvc.register_manual_mvc(workspace=h.parent, harness_path=h,
                                      source_file=h.parent / "keeper.go")
        self.assertEqual(rec["language"], "go")


if __name__ == "__main__":
    unittest.main(verbosity=2)
