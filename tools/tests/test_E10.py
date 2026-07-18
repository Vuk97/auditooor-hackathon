#!/usr/bin/env python3
"""E10 proof-leaf-to-message-type binding - regression + non-vacuity tests.

Pins the E10 mechanism detector added to tools/completeness-matrix-build.py
(scan_proof_leaf_type_binding / emit_proof_leaf_type_hypotheses): per bridge
leaf-digest SINK it backward-slices which declared message-TYPE discriminators
(leafType/kind/... enumerated by name OR by dataflow-usage as a class selector)
REACH the hashed leaf preimage, and emits one needs-fuzz row per UNBOUND
discriminator - a leaf usable under >1 message class (deposit vs exit).

Matrix (pure Solidity fixtures, no external toolchain):
  - leaf_complete.sol   -> 0 (complete-binding control; leafType packed).
  - leaf_unbound.sol    -> 1 (drops leafType from preimage -> cross-class collision;
                              enumerated_by=name).
  - leaf_usage_arm.sol  -> 1 (NON-vocabulary 'route' seen as a selector by dataflow;
                              enumerated_by=usage - net-new recall over a name list).
  - leaf_domain_only.sol-> 0 (DEDUP boundary: an unbound DOMAIN field is E3's cell;
                              E10 excludes identity fields).
  - generic_eip712.sol  -> 0 (FP guard: ordinary permit hash, no leaf/type).

Off-by-default: emit with no env / no force -> status 'off-by-default', 0 rows.
Dedup (A1 lesson - reuse, do NOT re-derive): rows are checked against a LIVE run
of the E3 scanner (scan_xchain_domain_binding); E10's type discriminators are
disjoint from E3's identity fields, so net-new rows are covered_by=None.

Mutation-verify (WS=polygon, DepositContractV2.sol): the real clean leaf builder
is silent; dropping leafType from the abi.encodePacked preimage in a mkdtemp COPY
flips it to 1 row on leafType. The shared ws is never mutated in place.

Non-vacuity:
  - test_mutate_type_class_predicate: neutralise the discriminator classifier; the
    name-enumerated UNBOUND case must collapse 1 -> 0.
  - test_mutate_reachability_predicate: neutralise the backward slice; the
    COMPLETE-binding control must flip 0 -> 1 (leafType no longer seen bound).
"""
from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import re
import shutil
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
FX = ROOT / "tests" / "fixtures" / "E10"
POLYGON_TGT = pathlib.Path(
    "/Users/wolf/audits/polygon/src/agglayer-contracts/contracts/lib/"
    "DepositContractV2.sol")


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "completeness_matrix_build_e10", TOOLS / "completeness-matrix-build.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _scan(tool, fixture: str):
    return tool.scan_proof_leaf_type_binding((FX / fixture).read_text(), fixture)


class E10ScanMatrixTest(unittest.TestCase):
    def setUp(self):
        self.tool = _load_tool()

    def test_complete_binding_control_clean(self):
        self.assertEqual(_scan(self.tool, "leaf_complete.sol"), [])

    def test_unbound_discriminator_fires_needs_fuzz(self):
        hits = _scan(self.tool, "leaf_unbound.sol")
        self.assertEqual(len(hits), 1, hits)
        h = hits[0]
        self.assertEqual(h["unbound_discriminator"], "leafType")
        self.assertEqual(h["function"], "getLeafValue")
        self.assertEqual(h["mechanism"], "proof-leaf-type-not-bound")
        self.assertEqual(h["impact"], "direct-theft-of-funds")
        self.assertEqual(h["verdict"], "needs-fuzz")
        self.assertTrue(h["advisory"])
        self.assertEqual(h["enumerated_by"], "name")

    def test_usage_arm_fires_on_non_vocabulary_name(self):
        # 'route' is not in any field-name vocabulary; dataflow-usage (route == 1|2)
        # is what makes it a discriminator - the net-new recall arm.
        hits = _scan(self.tool, "leaf_usage_arm.sol")
        self.assertEqual(len(hits), 1, hits)
        h = hits[0]
        self.assertEqual(h["unbound_discriminator"], "route")
        self.assertIn("usage", h["enumerated_by"])

    def test_domain_only_is_e3_cell_not_e10(self):
        # An unbound domain field is E3's cross-chain-domain-not-bound cell. E10
        # excludes identity fields -> must stay silent (dedup boundary honoured).
        self.assertEqual(_scan(self.tool, "leaf_domain_only.sol"), [])

    def test_generic_eip712_clean_fp_guard(self):
        self.assertEqual(_scan(self.tool, "generic_eip712.sol"), [])


class E10EmitTest(unittest.TestCase):
    def setUp(self):
        self.tool = _load_tool()

    def _emit(self, fixture: str, force):
        # Copy the fixture into a NON-vendor ws path (the emit skips test/mock/lib
        # dirs, so scanning the tests/fixtures tree directly would be filtered out).
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            (ws / ".auditooor").mkdir()
            (ws / "src").mkdir()
            shutil.copy2(FX / fixture, ws / "src" / fixture)
            acct = self.tool.emit_proof_leaf_type_hypotheses(
                ws, scan_root=ws, force=force)
            jl = ws / ".auditooor" / "proof_leaf_type_hypotheses.jsonl"
            rows = [json.loads(x) for x in
                    (jl.read_text().splitlines() if jl.exists() else []) if x.strip()]
            return acct, rows

    def test_off_by_default(self):
        self.assertNotIn("AUDITOOOR_PROOF_LEAF_TYPE_HYP", os.environ)
        acct, rows = self._emit("leaf_unbound.sol", force=False)
        self.assertEqual(acct["status"], "off-by-default")
        self.assertEqual(rows, [])

    def test_emit_net_new_distinct_from_e3(self):
        acct, rows = self._emit("leaf_unbound.sol", force=True)
        self.assertEqual(acct["status"], "ok")
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]["covered_by"])  # disjoint from E3 identity fields
        self.assertGreaterEqual(acct["distinct"], 1)
        self.assertEqual(rows[0]["verdict"], "needs-fuzz")

    def test_dedup_boundary_e3_does_not_own_leaftype(self):
        # The DEDUP JOIN is live, not a stub: prove the E3 scanner does NOT flag
        # leafType on the same source, so E10's row is genuinely net-new.
        src = (FX / "leaf_unbound.sol").read_text()
        e3_pairs = self.tool._e10_xchain_covered_pairs(src)
        self.assertNotIn(("getLeafValue", "leafType"), e3_pairs)


class E10MutationVerifyPolygonTest(unittest.TestCase):
    """WS=polygon TARGET=DepositContractV2.sol. Never mutates the shared ws in
    place: copies to a mkdtemp, mutates the COPY, confirms mutant fires + clean
    (copy AND real file) does not."""

    def setUp(self):
        self.tool = _load_tool()

    def test_polygon_leaf_mutation_kill(self):
        if not POLYGON_TGT.is_file():
            self.skipTest("polygon workspace absent")
        orig = POLYGON_TGT.read_text()
        # natural_instance: read-only confirm the real clean ws file is silent.
        self.assertEqual(
            self.tool.scan_proof_leaf_type_binding(orig, str(POLYGON_TGT)), [])
        d = pathlib.Path(tempfile.mkdtemp(prefix="e10_polygon_"))
        try:
            clean = d / "DepositContractV2.sol"
            shutil.copy2(POLYGON_TGT, clean)
            self.assertEqual(
                self.tool.scan_proof_leaf_type_binding(
                    clean.read_text(), str(clean)), [])
            # behavior-changing mutation: drop leafType from the leaf preimage
            # (keep the param). The 20-space-indented preimage line is unique.
            needle = "                    leafType,\n"
            self.assertEqual(clean.read_text().count(needle), 1)
            mut = d / "mut.sol"
            mut.write_text(clean.read_text().replace(needle, "", 1))
            hits = self.tool.scan_proof_leaf_type_binding(
                mut.read_text(), str(mut))
            self.assertEqual(len(hits), 1, hits)
            self.assertEqual(hits[0]["unbound_discriminator"], "leafType")
            self.assertEqual(hits[0]["verdict"], "needs-fuzz")
        finally:
            shutil.rmtree(d, ignore_errors=True)


class E10NonVacuityTest(unittest.TestCase):
    def setUp(self):
        self.tool = _load_tool()

    def test_mutate_type_class_predicate(self):
        # Neutralise the discriminator classifier: the name-enumerated UNBOUND case
        # must collapse 1 -> 0, proving the classifier is load-bearing.
        base = _scan(self.tool, "leaf_unbound.sol")
        self.assertEqual(len(base), 1)
        self.tool._E10_TYPE_RE = re.compile(r"(?!x)x")  # matches nothing
        # also disable the usage arm so leaf_unbound has no discriminator at all
        self.tool._e10_selector_usage = lambda p, b: False
        self.assertEqual(_scan(self.tool, "leaf_unbound.sol"), [])

    def test_mutate_reachability_predicate(self):
        # Neutralise the backward slice: the COMPLETE-binding control must flip
        # 0 -> 1 (leafType no longer seen reaching the preimage).
        self.assertEqual(_scan(self.tool, "leaf_complete.sol"), [])
        self.tool._xch_reachable_tokens = lambda pre, body: set()
        hits = _scan(self.tool, "leaf_complete.sol")
        self.assertEqual(len(hits), 1, hits)
        self.assertEqual(hits[0]["unbound_discriminator"], "leafType")


if __name__ == "__main__":
    unittest.main()
