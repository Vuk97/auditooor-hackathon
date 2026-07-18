#!/usr/bin/env python3
"""A9 - INTERRUPTION coupling edge (state-coupling-graph.py, kind='interruption').

NON-VACUOUS regression for the two-phase cross-fn split shape (strata SharesCooldown natural
instance): phase-1 CREATES a pending/request/cooldown-named record (push); the SETTLE (pop/
delete) lives ONLY in a SEPARATE finalize/cancel body; NO single fn writes all of S -> an
advisory `interruption` edge with verdict='needs-fuzz' (NO auto-credit).

Load-bearing predicates (mutating any ONE breaks a case below):
  1. SPLIT fixture -> fires (create fn + settle fn in DISTINCT bodies).
  2. ATOMIC fixture -> does NOT fire (a single fn creates+settles = FP-guard / flush-group
     boundary; drop the `atomic` guard and case 2 wrongly fires).
  3. verdict/advisory/auto_credit contract on the emitted edge (needs-fuzz, no credit).
  4. DEDUP: a flush-group edge covering the same (file, fn) suppresses the interruption hit
     (A1 - dedup emitted hits vs the named detector, not a covered_by re-derive).
"""
import importlib.util
import json
import sys
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent
_FIX = Path(__file__).resolve().parent / "fixtures" / "a9_interruption"


def _load():
    spec = importlib.util.spec_from_file_location("scg", _T / "state-coupling-graph.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules["scg"] = m
    spec.loader.exec_module(m)
    return m


def _mk_ws(tmp: Path, sol_src: str, fn: str = "requestRedeem") -> Path:
    (tmp / "src").mkdir(parents=True, exist_ok=True)
    rel = "src/C.sol"
    (tmp / rel).write_text(sol_src)
    (tmp / ".auditooor").mkdir(exist_ok=True)
    (tmp / ".auditooor" / "inscope_units.jsonl").write_text(
        json.dumps({"file": rel, "function": fn, "lang": "solidity"}) + "\n")
    return tmp


class TestA9Interruption(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        self.m._SOL_SVAR_CACHE.clear()

    def _run(self, tmp, src, **kw):
        self.m._SOL_SVAR_CACHE.clear()
        ws = _mk_ws(tmp, src)
        return self.m._interruption_edges(ws, **kw)

    def test_split_fires(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            edges = self._run(Path(d), (_FIX / "SplitCooldown.sol").read_text())
        self.assertEqual(len(edges), 1, "cross-fn split must emit exactly one edge")
        e = edges[0]
        self.assertEqual(e["kind"], "interruption")
        self.assertEqual(e["cell_a"], "activeRequests")
        self.assertIn("requestRedeem", [v["fn"] for v in e["violators"]])

    def test_verdict_contract(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            edges = self._run(Path(d), (_FIX / "SplitCooldown.sol").read_text())
        ev = edges[0]["evidence"]
        self.assertEqual(ev["verdict"], "needs-fuzz")
        self.assertTrue(ev["advisory"])
        self.assertFalse(ev["auto_credit"])
        self.assertTrue(ev["cross_fn_split"])
        self.assertTrue(ev["no_atomic_writer"])

    def test_atomic_does_not_fire(self):
        # The FP-guard / flush-group boundary: a single fn that CREATES and SETTLES the record
        # is atomic -> NOT an interruption. This is the predicate-load-bearing counter-case.
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            edges = self._run(Path(d), (_FIX / "AtomicCooldown.sol").read_text())
        self.assertEqual(edges, [], "atomic create+settle in one body must NOT fire")

    def test_record_ops_predicate_nonvacuous(self):
        # Direct predicate check: create=push, settle=pop/delete; mutate the body -> flips.
        c, s = self.m._sol_record_ops(
            "TRequest[] storage r = activeRequests[to]; r.push(x);", "activeRequests")
        self.assertTrue(c and not s)
        c, s = self.m._sol_record_ops(
            "TRequest[] storage r = activeRequests[to]; r.pop();", "activeRequests")
        self.assertTrue(s and not c)
        c, s = self.m._sol_record_ops("uint x = 1;", "activeRequests")
        self.assertFalse(c or s)

    def test_dedup_vs_flush_group(self):
        # A1 dedup boundary: a flush-group edge already covering (file, requestRedeem)
        # suppresses the interruption emission (no re-derive of a covered signal).
        import tempfile
        flush = [{
            "kind": "flush-group",
            "violators": [{"file": "src/C.sol", "fn": "requestRedeem"}],
        }]
        with tempfile.TemporaryDirectory() as d:
            self.m._SOL_SVAR_CACHE.clear()
            ws = _mk_ws(Path(d), (_FIX / "SplitCooldown.sol").read_text())
            edges = self.m._interruption_edges(ws, flush_edges=flush)
        self.assertEqual(edges, [], "flush-group coverage must dedup the interruption hit")

    def test_schema_valid(self):
        import tempfile
        import importlib.util as _il
        sp = _il.spec_from_file_location("scs", _T / "state_coupling_schema.py")
        scs = _il.module_from_spec(sp)
        sp.loader.exec_module(scs)
        with tempfile.TemporaryDirectory() as d:
            edges = self._run(Path(d), (_FIX / "SplitCooldown.sol").read_text())
        ok, errs = scs.validate(edges[0])
        self.assertTrue(ok, f"edge fails schema: {errs}")
        self.assertIn("interruption", scs.COUPLING_KINDS)


if __name__ == "__main__":
    unittest.main()
