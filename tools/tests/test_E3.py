#!/usr/bin/env python3
"""E3 cross-chain-domain-not-bound hypothesis emitter - regression + non-vacuity.

Pins the E3 mechanism detector added to tools/completeness-matrix-build.py
(scan_xchain_domain_binding / emit_xchain_domain_binding_hypotheses): per
keccak/abi.encode(Packed) DIGEST sink it backward-slices which declared
cross-chain identity fields (src+dst domain + nonce + sender/recipient) REACH
the hashed preimage and emits one needs-fuzz row per UNBOUND field.

Matrix (pure Solidity fixtures, no external toolchain):
  - msg_complete.sol     -> 0 (complete-binding control; all fields bound).
  - msg_unbound.sol      -> 1 (drops _originDomain -> cross-origin replay seam).
  - digest_transitive.sol-> 0 (FP guard: _origin bound via a domainHash local).
  - body_construction.sol-> 0 (FP guard: abi.encode is a dispatched body, no
                                keccak/return digest sink).

Off-by-default: emit with no env / no force -> status 'off-by-default', 0 rows.
Dedup (A1 lesson - reuse, do not re-derive): rows are checked against the LIVE
wave17 detector (bridge_message_domain_binding_fire28); a net-new row (wave17
silent) is covered_by=None and counts toward `distinct`.

Non-vacuity:
  - test_mutate_reachability_predicate: neutralise the backward slice; the
    COMPLETE-binding control must then flip 0 -> >0 (fields no longer seen bound),
    proving the reachability predicate is load-bearing.
  - test_mutate_identity_predicate: neutralise the identity class; the UNBOUND
    case must collapse 1 -> 0, proving the must-bind classifier is load-bearing.
"""
from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import re
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
FX = ROOT / "tests" / "fixtures" / "E3"
WAVE17_POS = (ROOT / "detectors" / "test_fixtures" / "positive"
              / "bridge_message_domain_binding_fire28.sol")


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "completeness_matrix_build_e3", TOOLS / "completeness-matrix-build.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _scan(tool, fixture: str):
    return tool.scan_xchain_domain_binding((FX / fixture).read_text(), fixture)


class E3ScanMatrixTest(unittest.TestCase):
    def setUp(self):
        self.tool = _load_tool()

    def test_complete_binding_control_clean(self):
        self.assertEqual(_scan(self.tool, "msg_complete.sol"), [])

    def test_unbound_field_fires_needs_fuzz(self):
        hits = _scan(self.tool, "msg_unbound.sol")
        self.assertEqual(len(hits), 1, hits)
        h = hits[0]
        self.assertEqual(h["unbound_field"], "_originDomain")
        self.assertEqual(h["function"], "formatMessage")
        self.assertEqual(h["mechanism"], "cross-chain-domain-not-bound")
        self.assertEqual(h["verdict"], "needs-fuzz")
        self.assertTrue(h["advisory"])
        self.assertTrue(h["identity_field"])

    def test_transitive_binding_clean_fp_guard(self):
        # _origin reaches the digest through `_domainHash = domainHash(_origin,..)`.
        self.assertEqual(_scan(self.tool, "digest_transitive.sol"), [])

    def test_body_construction_clean_sink_guard(self):
        # abi.encode here is a dispatched body, not a keccak/return digest sink.
        self.assertEqual(_scan(self.tool, "body_construction.sol"), [])


class E3EmitTest(unittest.TestCase):
    def setUp(self):
        self.tool = _load_tool()

    def _emit(self, scan_root, force):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            (ws / ".auditooor").mkdir()
            acct = self.tool.emit_xchain_domain_binding_hypotheses(
                ws, scan_root=scan_root, force=force)
            jl = ws / ".auditooor" / "xchain_domain_binding_hypotheses.jsonl"
            rows = [json.loads(x) for x in
                    (jl.read_text().splitlines() if jl.exists() else []) if x.strip()]
            return acct, rows

    def test_off_by_default(self):
        # No env, no force -> producer does nothing (never spams a workspace).
        self.assertNotIn("AUDITOOOR_XCHAIN_DOMAIN_BIND_HYP", os.environ)
        acct, rows = self._emit(FX / "msg_unbound.sol", force=False)
        self.assertEqual(acct["status"], "off-by-default")
        self.assertEqual(rows, [])

    def test_emit_net_new_distinct_from_wave17(self):
        acct, rows = self._emit(FX / "msg_unbound.sol", force=True)
        self.assertEqual(acct["status"], "ok")
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]["covered_by"])  # wave17 silent on a pure format fn
        self.assertGreaterEqual(acct["distinct"], 1)
        self.assertEqual(rows[0]["verdict"], "needs-fuzz")

    def test_dedup_credits_wave17_overlap(self):
        # The wave17 positive fixture is flagged by BOTH detectors on the same fn;
        # our row must be tagged covered_by (dedup live, not a silent no-op stub).
        if not WAVE17_POS.is_file():
            self.skipTest("wave17 positive fixture absent")
        covered = self.tool._xch_wave17_covered_fns(WAVE17_POS.read_text())
        self.assertIn("receiveBridgeMessage", covered)
        acct, rows = self._emit(WAVE17_POS, force=True)
        overlap = [r for r in rows if r["function"] == "receiveBridgeMessage"]
        self.assertTrue(overlap)
        self.assertTrue(all(
            r["covered_by"] == "bridge-message-domain-binding-fire28" for r in overlap))


class E3NonVacuityTest(unittest.TestCase):
    def setUp(self):
        self.tool = _load_tool()

    def test_mutate_reachability_predicate(self):
        # Neutralise the backward slice -> nothing is seen as bound, so the
        # COMPLETE-binding control must flip 0 -> >0. Proves reachability is real.
        base = _scan(self.tool, "msg_complete.sol")
        self.assertEqual(base, [])
        orig = self.tool._xch_reachable_tokens
        self.tool._xch_reachable_tokens = lambda preimage, body: set()
        try:
            broken = _scan(self.tool, "msg_complete.sol")
        finally:
            self.tool._xch_reachable_tokens = orig
        self.assertGreater(len(broken), 0,
                           "reachability predicate is not load-bearing (vacuous)")

    def test_mutate_identity_predicate(self):
        # Neutralise the must-bind identity classifier -> the UNBOUND case has no
        # field to fire on, collapsing 1 -> 0. Proves the classifier is load-bearing.
        base = _scan(self.tool, "msg_unbound.sol")
        self.assertEqual(len(base), 1)
        orig = self.tool._XCH_IDENTITY_RE
        self.tool._XCH_IDENTITY_RE = re.compile(r"\bZZ_NEVER_MATCHES_ZZ\b")
        try:
            broken = _scan(self.tool, "msg_unbound.sol")
        finally:
            self.tool._XCH_IDENTITY_RE = orig
        self.assertEqual(broken, [],
                         "identity classifier is not load-bearing (vacuous)")


if __name__ == "__main__":
    unittest.main()
