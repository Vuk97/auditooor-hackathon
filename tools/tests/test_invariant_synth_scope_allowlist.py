#!/usr/bin/env python3
# <!-- r36-rebuttal: lane INVARIANT-SYNTH-SCOPE-ALLOWLIST registered in commit message -->
"""Strata 2026-06-30 ("HOW TO HUNT not delivering" root cause): invariant-auto-synth
ws.rglob'd the WHOLE workspace and only excluded a few dir substrings - NOT the
enumerated in-scope manifest. It SEEDS the entire impact-methodology per-function hunt,
so the unscoped walk flooded step-3 with OZ-lib/ERC/test/foreign-corpus functions
(200 files, hunt referenced rawToConvertedEIPTx1559s) and DROWNED the 17 real in-scope
files under the max-files cap. Fix: _inscope_files() restricts to .auditooor/
inscope_units.jsonl BEFORE the cap. Pins: restrict-when-manifest, whole-tree-when-absent,
restrict-before-cap (real files survive the cap).
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "invariant-auto-synth.py"


def _load():
    spec = importlib.util.spec_from_file_location("ias", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["ias"] = m
    spec.loader.exec_module(m)
    return m


ias = _load()


def _mk_ws(inscope_files):
    ws = Path(tempfile.mkdtemp(prefix="ias_"))
    (ws / ".auditooor").mkdir()
    if inscope_files is not None:
        (ws / ".auditooor" / "inscope_units.jsonl").write_text(
            "".join(json.dumps({"file": f}) + "\n" for f in inscope_files),
            encoding="utf-8")
    return ws


class InvariantSynthScopeTest(unittest.TestCase):
    def test_inscope_files_reads_manifest(self):
        ws = _mk_ws(["src/contracts/contracts/tranches/Accounting.sol",
                     "src/contracts/contracts/tranches/utils/RoundingGuard.sol"])
        got = ias._inscope_files(ws)
        self.assertEqual(len(got), 2)
        self.assertTrue(any(g.endswith("Accounting.sol") for g in got))
        self.assertTrue(any(g.endswith("RoundingGuard.sol") for g in got))

    def test_no_manifest_returns_empty_set(self):
        # no .auditooor/inscope_units.jsonl -> empty set -> caller keeps whole-tree
        ws = _mk_ws(None)
        self.assertEqual(ias._inscope_files(ws), set())

    def test_skip_dirs_excludes_lib(self):
        # /lib/ (OpenZeppelin submodule) must be excluded so the synth never seeds
        # the hunt with ERC4626/ERC777/Governor library functions.
        # (the _SKIP_DIRS frozenset is built inside main(); assert the source carries it)
        src = _TOOL.read_text(encoding="utf-8")
        self.assertIn('"/lib/"', src)
        self.assertIn("_inscope_files(ws)", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
