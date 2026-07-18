#!/usr/bin/env python3
"""Inline-assembly / Yul detection + asm-scoped sink oracle - regression + mutation.

Pins the Glider `is_assembly` analog added to ``tools/slither_predicates.py``:

  - ``has_inline_assembly`` / ``assembly_nodes`` - inline-assembly (Yul) detection.
  - ``asm_delegatecalls``    - Yul-level delegatecall (proxy/upgrade backdoor) the
                               SOLIDITY-level `has_low_level_delegatecall` is blind to.
  - ``asm_sstores``          - LITERAL-slot sstore (storage-slot collision shape);
                               a declared-var `.slot` sstore is NOT flagged.
  - ``asm_raw_calls``        - raw value-moving Yul `call(`.
  - ``asm_suspect_sinks`` / ``closure_asm_suspect_sinks`` - aggregate + closure entry.

Honesty (R80): the semantic cases require a real Slither compile of the in-tree
fixtures; if Slither is not importable they SKIP (no faked pass). The DEGRADE path
runs WITHOUT Slither. Mutation evidence:
``test_mutation_solidity_delegatecall_to_yul_flips_annotation`` rewrites a SOLIDITY-
level `.delegatecall(data)` into a Yul `delegatecall(...)` and asserts the asm
oracle flips [] -> [hit] (closing the blind spot the solidity-only predicate had).
Never-false-positive: declared-var `.slot` sstore + memory-only asm + no-asm all
yield [] / False.
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
        "slither_predicates_asm", TOOLS / "slither_predicates.py"
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
    "slither-analyzer not importable; asm IR tests need a real compile",
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


# ─── Slot-literal classifier (pure, no Slither needed) ───────────────────────


class SlotLiteralClassifierTest(unittest.TestCase):
    def test_numeric_literal_is_literal(self):
        self.assertTrue(sp._asm_slot_is_literal("0x0"))
        self.assertTrue(sp._asm_slot_is_literal("0xdeadbeef"))
        self.assertTrue(sp._asm_slot_is_literal("42"))

    def test_dot_slot_declared_var_is_not_literal(self):
        # the var's own canonical compiler slot -> safe -> not literal.
        self.assertFalse(sp._asm_slot_is_literal("value.slot"))
        self.assertFalse(sp._asm_slot_is_literal("balances.slot"))
        self.assertFalse(sp._asm_slot_is_literal("x .slot"))

    def test_constant_arith_with_literal_is_literal(self):
        # a hardcoded base slot with offset arithmetic (no .slot) -> collision risk.
        self.assertTrue(sp._asm_slot_is_literal("add(0x10, i)"))

    def test_bare_local_var_is_not_literal(self):
        # a computed local (e.g. a keccak result) is NOT a literal -> not flagged.
        self.assertFalse(sp._asm_slot_is_literal("s"))
        self.assertFalse(sp._asm_slot_is_literal("computedSlot"))

    def test_empty_is_not_literal(self):
        self.assertFalse(sp._asm_slot_is_literal(""))
        self.assertFalse(sp._asm_slot_is_literal("   "))


# ─── Degrade path (no Slither needed) ────────────────────────────────────────


class AsmDegradeTest(unittest.TestCase):
    class _Dummy:
        pass

    def test_has_inline_assembly_degrades(self):
        self.assertTrue(sp.is_degraded(sp.has_inline_assembly(self._Dummy())))

    def test_asm_delegatecalls_degrades(self):
        self.assertTrue(sp.is_degraded(sp.asm_delegatecalls(self._Dummy())))

    def test_asm_sstores_degrades(self):
        self.assertTrue(sp.is_degraded(sp.asm_sstores(self._Dummy())))

    def test_asm_suspect_sinks_degrades(self):
        self.assertTrue(sp.is_degraded(sp.asm_suspect_sinks(self._Dummy())))

    def test_closure_asm_suspect_sinks_degrades(self):
        self.assertTrue(
            sp.is_degraded(sp.closure_asm_suspect_sinks(self._Dummy()))
        )


# ─── Semantic path (real Slither compile of fixtures) ────────────────────────


@SKIP_NO_SLITHER
class AsmOracleTest(unittest.TestCase):
    def test_a_yul_delegatecall_is_suspect(self):
        # (a) Yul delegatecall -> suspect, kind=delegatecall.
        sl = _compile(FX / "asm_delegatecall_suspect.sol")
        _, fn = _get_fn(sl, "AsmDelegatecallSuspect", "forward")
        self.assertIsNotNone(fn)
        self.assertIs(sp.has_inline_assembly(fn), True)
        leads = sp.asm_delegatecalls(fn)
        self.assertFalse(sp.is_degraded(leads))
        self.assertEqual(len(leads), 1, leads)
        d = leads[0]
        self.assertEqual(d["kind"], "delegatecall")
        self.assertIsNone(d["slot"])
        self.assertIsNotNone(d["line"])
        # surfaced via the aggregate sink oracle too.
        sinks = sp.asm_suspect_sinks(fn)
        self.assertEqual([s["kind"] for s in sinks], ["delegatecall"])
        # and NOT seen by the solidity-level delegatecall predicate.
        self.assertIs(sp.has_low_level_delegatecall(fn), False)

    def test_b_literal_slot_sstore_is_suspect(self):
        # (b) sstore(0x0, v) literal slot -> suspect, kind=sstore-literal, literal=True.
        sl = _compile(FX / "asm_sstore_literal_suspect.sol")
        _, fn = _get_fn(sl, "AsmSstoreLiteralSuspect", "setRaw")
        leads = sp.asm_sstores(fn)
        self.assertFalse(sp.is_degraded(leads))
        self.assertEqual(len(leads), 1, leads)
        d = leads[0]
        self.assertEqual(d["kind"], "sstore-literal")
        self.assertTrue(d["literal"])
        self.assertEqual(d["slot"], "0x0")
        self.assertIsNotNone(d["line"])

    def test_c_declared_var_slot_sstore_not_flagged(self):
        # (c) sstore(value.slot, v) declared-var slot -> NOT flagged (never-FP).
        sl = _compile(FX / "asm_sstore_declared_clean.sol")
        _, fn = _get_fn(sl, "AsmSstoreDeclaredClean", "setVal")
        self.assertIs(sp.has_inline_assembly(fn), True)  # it HAS asm...
        self.assertEqual(sp.asm_sstores(fn), [])         # ...but the sstore is safe.
        self.assertEqual(sp.asm_suspect_sinks(fn), [])

    def test_d_memory_only_asm_not_flagged(self):
        # (d) memory-only asm (mload/mstore) -> has asm but NO suspect sink.
        sl = _compile(FX / "asm_memory_only_clean.sol")
        _, fn = _get_fn(sl, "AsmMemoryOnlyClean", "sum")
        self.assertIs(sp.has_inline_assembly(fn), True)
        self.assertEqual(sp.asm_delegatecalls(fn), [])
        self.assertEqual(sp.asm_sstores(fn), [])
        self.assertEqual(sp.asm_raw_calls(fn), [])
        self.assertEqual(sp.asm_suspect_sinks(fn), [])

    def test_e_no_asm_not_flagged(self):
        # (e) no inline assembly -> has_inline_assembly False, no suspect sink.
        sl = _compile(FX / "asm_none_clean.sol")
        _, fn = _get_fn(sl, "AsmNoneClean", "deposit")
        self.assertIs(sp.has_inline_assembly(fn), False)
        self.assertEqual(sp.asm_suspect_sinks(fn), [])

    def test_closure_entry_finds_own_body(self):
        sl = _compile(FX / "asm_delegatecall_suspect.sol")
        _, fn = _get_fn(sl, "AsmDelegatecallSuspect", "forward")
        leads = sp.closure_asm_suspect_sinks(fn)
        self.assertEqual(len(leads), 1)
        self.assertEqual(leads[0]["at_fn"], "forward")
        self.assertEqual(leads[0]["kind"], "delegatecall")


@SKIP_NO_SLITHER
class AsmMutationTest(unittest.TestCase):
    """Non-vacuity + blind-spot closure: a SOLIDITY-level `.delegatecall(data)`
    is caught by `has_low_level_delegatecall` but MISSED by `asm_delegatecalls`.
    Rewriting it into a Yul `delegatecall(...)` must flip the asm oracle [] -> [hit]
    (the previously-missed proxy backdoor is now caught)."""

    def test_mutation_solidity_delegatecall_to_yul_flips_annotation(self):
        base = FX / "asm_solidity_delegatecall_mutation_base.sol"
        src = base.read_text(encoding="utf-8")
        sl = _compile(base)
        _, fn = _get_fn(sl, "AsmSolidityDelegatecallBase", "forward")
        # baseline: solidity-level delegatecall is SEEN by the solidity predicate
        # but the asm oracle correctly does NOT fire (no inline assembly).
        self.assertIs(sp.has_low_level_delegatecall(fn), True)
        self.assertIs(sp.has_inline_assembly(fn), False)
        self.assertEqual(sp.asm_delegatecalls(fn), [])

        # mutate: replace the solidity `.delegatecall(data)` with a Yul delegatecall.
        mutated = src.replace(
            "        (ok, ret) = implementation.delegatecall(data);",
            "        address impl = implementation;\n"
            "        assembly {\n"
            "            calldatacopy(0, data.offset, data.length)\n"
            "            ok := delegatecall(gas(), impl, 0, data.length, 0, 0)\n"
            "        }\n"
            "        ret = ret;",
        )
        self.assertNotEqual(mutated, src, "mutation pattern did not match fixture")
        with tempfile.TemporaryDirectory() as td:
            mp = pathlib.Path(td) / "asm_mut.sol"
            mp.write_text(mutated, encoding="utf-8")
            msl = _compile(mp)
            _, mfn = _get_fn(msl, "AsmSolidityDelegatecallBase", "forward")
            self.assertIs(sp.has_inline_assembly(mfn), True)
            leads = sp.asm_delegatecalls(mfn)
            self.assertEqual(
                len(leads), 1,
                "asm oracle did not catch the Yul delegatecall after mutation "
                "(blind spot NOT closed / vacuous!)",
            )
            self.assertEqual(leads[0]["kind"], "delegatecall")


if __name__ == "__main__":
    unittest.main(verbosity=2)
