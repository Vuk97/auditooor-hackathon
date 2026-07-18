#!/usr/bin/env python3
"""Regression: a directory whose EVERY .sol carries the gen-invariants.sh scaffold header
(the scaffold STAGING area, e.g. <ws>/test/Invariant_*.t.sol) is excluded from harness
enumeration - it is not one of OUR canonical hand-authored economic-invariant harnesses
(chimera_harnesses/, header-free). A mixed filled+unfilled staging dir previously slipped
through _is_unfilled_scaffold_harness and enumerated with mut=False, wrongly failing the
gate. Header-free dirs (real harnesses) are unaffected."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_MOD = _HERE.parent / "invariant-fuzz-completeness.py"
_spec = importlib.util.spec_from_file_location("ifc_scaffold", _MOD)
_m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_m)

_HDR = "// Auto-scaffolded by tools/gen-invariants.sh on 2026-06-30T10:00:00Z\n"


class TestScaffoldStagingExclusion(unittest.TestCase):
    def _dir(self, files: dict) -> Path:
        d = Path(tempfile.mkdtemp())
        for name, body in files.items():
            (d / name).write_text(body)
        return d

    def test_all_scaffold_dir_excluded(self):
        # mixed: 2 unfilled placeholders + 1 filled - all carry the header => staging
        d = self._dir({
            "Invariant_A.t.sol": _HDR + "contract A { function invariant_placeholder() public {} }",
            "Invariant_B.t.sol": _HDR + "contract B { function invariant_placeholder() public {} }",
            "Invariant_C.t.sol": _HDR + "contract C { function invariant_real_conservation() public {} }",
        })
        self.assertTrue(_m._is_gen_invariants_scaffold_staging_dir(d))

    def test_header_free_harness_not_excluded(self):
        # a canonical hand-authored harness (no scaffold header) is NOT staging
        d = self._dir({
            "MyConservation.sol": "contract MyConservation { function echidna_conservation() public {} }",
            "Sanity.t.sol": "contract SanityTest { function test_x() public {} }",
        })
        self.assertFalse(_m._is_gen_invariants_scaffold_staging_dir(d))

    def test_mixed_header_and_headerfree_not_excluded(self):
        # if ANY .sol lacks the header, the dir holds real code -> not pure staging
        d = self._dir({
            "Scaffold.t.sol": _HDR + "contract S { function invariant_placeholder() public {} }",
            "Real.sol": "contract R { function echidna_real() public {} }",
        })
        self.assertFalse(_m._is_gen_invariants_scaffold_staging_dir(d))

    def test_empty_dir_not_excluded(self):
        self.assertFalse(_m._is_gen_invariants_scaffold_staging_dir(self._dir({})))


if __name__ == "__main__":
    unittest.main()
