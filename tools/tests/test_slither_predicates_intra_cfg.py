#!/usr/bin/env python3
"""Intra-procedural CFG navigation + same-fn-CEI / unbounded-loop oracle - Glider
gap #5 (final). Regression + mutation pinning of the predicates added to
``tools/slither_predicates.py``:

  - ``cfg_ordered_nodes``   - sons-walk execution-order CFG traversal.
  - ``dominators`` / ``node_dominates`` - dominator analysis over the CFG.
  - ``loop_headers``        - STARTLOOP / IFLOOP detection (reuses son_true/false).
  - ``intra_fn_cei``        - same-fn external-call-THEN-state-write oracle
                              (conservative: write-before-call / guarded = NOT
                              flagged; never-false-positive).
  - ``unbounded_loops``     - attacker-growable `.length`-bound loop oracle
                              (conservative: const / param / local-cap = NOT
                              flagged).
  - ``closure_intra_fn_cei`` / ``closure_unbounded_loops`` - own-body + forward
                              closure variants.

Honesty (R80): the semantic cases require a real Slither compile of the in-tree
fixtures; if Slither is not importable they SKIP (no faked pass). The DEGRADE path
is tested without Slither. Mutation evidence:
``test_mutation_move_write_after_call_flips_annotation`` moves a state-write from
BEFORE to AFTER the external call and asserts intra_cei flips False->True
(non-vacuity). Never-false-positive: write-before-call, nonReentrant-guarded,
constant-loop and param-loop all yield no annotation.

This COMPLEMENTS the cross-fn closure reentrancy oracle (has_guard_in_closure /
callee_closure), which reasons over A->B call EDGES and is blind to A's own
internal statement ORDER; it does NOT duplicate it.
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
FX = ROOT / "tests" / "fixtures" / "callgraph_closure"

if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))


def _load_sp():
    spec = importlib.util.spec_from_file_location(
        "slither_predicates", TOOLS / "slither_predicates.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


sp = _load_sp()


def _slither_available() -> bool:
    try:
        import slither  # noqa: F401

        return True
    except Exception:
        return False


SKIP_NO_SLITHER = unittest.skipUnless(
    _slither_available(),
    "slither-analyzer not importable; intra-CFG tests need a real compile",
)


def _compile(path: pathlib.Path):
    from slither import Slither

    return Slither(str(path))


def _get_fn(sl, cname, fname):
    for c in sl.contracts:
        if c.name == cname:
            for f in c.functions:
                if f.name == fname:
                    return c, f
    return None, None


# ─── Degrade path (no Slither needed) ────────────────────────────────────────


class IntraCfgDegradeTest(unittest.TestCase):
    """R80: a non-navigable input degrades (distinct sentinel), never a guess."""

    class _Dummy:
        pass

    def test_cfg_ordered_nodes_degrades(self):
        self.assertTrue(sp.is_degraded(sp.cfg_ordered_nodes(self._Dummy())))

    def test_dominators_degrades(self):
        self.assertTrue(sp.is_degraded(sp.dominators(self._Dummy())))

    def test_loop_headers_degrades(self):
        self.assertTrue(sp.is_degraded(sp.loop_headers(self._Dummy())))

    def test_intra_fn_cei_degrades(self):
        self.assertTrue(sp.is_degraded(sp.intra_fn_cei(self._Dummy())))

    def test_unbounded_loops_degrades(self):
        self.assertTrue(sp.is_degraded(sp.unbounded_loops(self._Dummy())))

    def test_closure_variants_degrade(self):
        self.assertTrue(sp.is_degraded(sp.closure_intra_fn_cei(self._Dummy())))
        self.assertTrue(sp.is_degraded(sp.closure_unbounded_loops(self._Dummy())))

    def test_node_dominates_false_on_degraded_map(self):
        self.assertFalse(sp.node_dominates(sp.DEGRADED, object(), object()))
        self.assertFalse(sp.node_dominates(None, object(), object()))


# ─── Semantic path: ordered CFG navigation ───────────────────────────────────


@SKIP_NO_SLITHER
class CfgNavigationTest(unittest.TestCase):
    def test_ordered_nodes_start_at_entry(self):
        sl = _compile(FX / "cei_ext_then_write_suspect.sol")
        _, fn = _get_fn(sl, "CeiExtThenWriteSuspect", "withdraw")
        ordered = sp.cfg_ordered_nodes(fn)
        self.assertFalse(sp.is_degraded(ordered))
        self.assertTrue(ordered)
        first = str(getattr(ordered[0], "type", "")).upper()
        self.assertIn("ENTRYPOINT", first)
        # Every declared node is present (no node silently dropped).
        self.assertEqual(len(ordered), len(list(fn.nodes)))

    def test_ext_call_precedes_state_write_in_order(self):
        # The whole point of ordered traversal: the ext-call node comes before the
        # state-write node on the CFG path (which the flat declaration walk does
        # not guarantee).
        sl = _compile(FX / "cei_ext_then_write_suspect.sol")
        _, fn = _get_fn(sl, "CeiExtThenWriteSuspect", "withdraw")
        ordered = sp.cfg_ordered_nodes(fn)
        ext_idx = write_idx = None
        for i, n in enumerate(ordered):
            if sp._node_is_external_call(n) and ext_idx is None:
                ext_idx = i
            if list(sp._node_state_writes(n)) and write_idx is None:
                write_idx = i
        self.assertIsNotNone(ext_idx)
        self.assertIsNotNone(write_idx)
        self.assertLess(ext_idx, write_idx, "ext call must precede state-write in CFG order")

    def test_loop_headers_finds_ifloop(self):
        sl = _compile(FX / "loop_attacker_growable_suspect.sol")
        _, fn = _get_fn(sl, "LoopAttackerGrowableSuspect", "distribute")
        headers = sp.loop_headers(fn)
        self.assertFalse(sp.is_degraded(headers))
        types = {str(getattr(h, "type", "")).upper().rsplit(".", 1)[-1] for h in headers}
        self.assertIn("IFLOOP", types)

    def test_dominators_entry_dominates_all(self):
        sl = _compile(FX / "cei_ext_then_write_suspect.sol")
        _, fn = _get_fn(sl, "CeiExtThenWriteSuspect", "withdraw")
        dom = sp.dominators(fn)
        self.assertFalse(sp.is_degraded(dom))
        entry = getattr(fn, "entry_point", None) or list(fn.nodes)[0]
        # entry dominates every node.
        for n in fn.nodes:
            self.assertTrue(sp.node_dominates(dom, entry, n),
                            "entry node must dominate every node")


# ─── Semantic path: same-fn CEI oracle ───────────────────────────────────────


@SKIP_NO_SLITHER
class IntraFnCeiOracleTest(unittest.TestCase):
    def test_a_ext_then_write_is_suspect(self):
        # (a) ext call THEN state-write, no guard -> intra_cei_suspect.
        sl = _compile(FX / "cei_ext_then_write_suspect.sol")
        _, fn = _get_fn(sl, "CeiExtThenWriteSuspect", "withdraw")
        res = sp.intra_fn_cei(fn)
        self.assertFalse(sp.is_degraded(res))
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["var"], "balances")
        self.assertIsNotNone(res[0]["ext_call_line"])
        self.assertIsNotNone(res[0]["state_write_line"])
        self.assertGreater(res[0]["state_write_line"], res[0]["ext_call_line"])

    def test_b_write_before_call_never_fp(self):
        # (b) CEI-correct write-before-call -> NOT flagged (never-false-positive).
        sl = _compile(FX / "cei_write_before_call_clean.sol")
        _, fn = _get_fn(sl, "CeiWriteBeforeCallClean", "withdraw")
        self.assertEqual(sp.intra_fn_cei(fn), [])

    def test_c_nonreentrant_guarded_never_fp(self):
        # (c) ext-then-write but nonReentrant-guarded -> NOT flagged.
        sl = _compile(FX / "cei_nonreentrant_guarded_clean.sol")
        _, fn = _get_fn(sl, "CeiNonReentrantGuardedClean", "withdraw")
        self.assertEqual(sp.intra_fn_cei(fn), [])

    def test_closure_intra_cei_own_body_first(self):
        sl = _compile(FX / "cei_ext_then_write_suspect.sol")
        _, fn = _get_fn(sl, "CeiExtThenWriteSuspect", "withdraw")
        res = sp.closure_intra_fn_cei(fn)
        self.assertFalse(sp.is_degraded(res))
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["at_fn"], "withdraw")


# ─── Semantic path: unbounded-loop oracle ────────────────────────────────────


@SKIP_NO_SLITHER
class UnboundedLoopOracleTest(unittest.TestCase):
    def test_d_attacker_growable_length_is_suspect(self):
        # (d) loop bounded by attacker-growable state-array `.length` with an
        # effect inside -> unbounded_loop_suspect.
        sl = _compile(FX / "loop_attacker_growable_suspect.sol")
        _, fn = _get_fn(sl, "LoopAttackerGrowableSuspect", "distribute")
        res = sp.unbounded_loops(fn)
        self.assertFalse(sp.is_degraded(res))
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["bound_var"], "users")
        self.assertIsNotNone(res[0]["loop_line"])

    def test_e_constant_bound_never_fp(self):
        # (e) constant-bounded loop -> NOT flagged (reads no state var in bound).
        sl = _compile(FX / "loop_constant_bound_clean.sol")
        _, fn = _get_fn(sl, "LoopConstantBoundClean", "constLoop")
        self.assertEqual(sp.unbounded_loops(fn), [])

    def test_e_param_bound_never_fp(self):
        # (e') parameter-bounded loop -> NOT flagged.
        sl = _compile(FX / "loop_constant_bound_clean.sol")
        _, fn = _get_fn(sl, "LoopConstantBoundClean", "paramLoop")
        self.assertEqual(sp.unbounded_loops(fn), [])

    def test_closure_unbounded_loops_own_body_first(self):
        sl = _compile(FX / "loop_attacker_growable_suspect.sol")
        _, fn = _get_fn(sl, "LoopAttackerGrowableSuspect", "distribute")
        res = sp.closure_unbounded_loops(fn)
        self.assertFalse(sp.is_degraded(res))
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["at_fn"], "distribute")


# ─── Mutation evidence (non-vacuity) ─────────────────────────────────────────


@SKIP_NO_SLITHER
class IntraCeiMutationTest(unittest.TestCase):
    """Non-vacuity: moving the state-write from BEFORE to AFTER the external call
    must flip intra_cei False->True."""

    def test_mutation_move_write_after_call_flips_annotation(self):
        src = (FX / "cei_write_before_call_clean.sol").read_text(encoding="utf-8")
        sl = _compile(FX / "cei_write_before_call_clean.sol")
        _, fn = _get_fn(sl, "CeiWriteBeforeCallClean", "withdraw")
        # Base: CEI-correct -> NOT flagged.
        self.assertEqual(sp.intra_fn_cei(fn), [])

        mutated = src.replace(
            '''        balances[msg.sender] = 0;   // EFFECT first
        (bool ok, ) = msg.sender.call{value: amt}("");  // INTERACTION last
        require(ok, "send failed");''',
            '''        (bool ok, ) = msg.sender.call{value: amt}("");  // INTERACTION moved first
        require(ok, "send failed");
        balances[msg.sender] = 0;   // EFFECT moved AFTER the call (CEI violation)''',
        )
        self.assertNotEqual(mutated, src, "mutation pattern did not match fixture")
        with tempfile.TemporaryDirectory() as td:
            mp = pathlib.Path(td) / "cei_write_before_call_clean.sol"
            mp.write_text(mutated, encoding="utf-8")
            msl = _compile(mp)
            _, mfn = _get_fn(msl, "CeiWriteBeforeCallClean", "withdraw")
            res = sp.intra_fn_cei(mfn)
            self.assertEqual(len(res), 1,
                             "annotation did not flip False->True under "
                             "write-before->after-call mutation (vacuous!)")
            self.assertEqual(res[0]["var"], "balances")


if __name__ == "__main__":
    unittest.main(verbosity=2)
