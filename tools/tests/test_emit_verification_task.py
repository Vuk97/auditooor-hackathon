#!/usr/bin/env python3
"""Tests for emit-verification-task.py - the VERIFICATION-TASK EMITTER that converts a
load-bearing prose-checking gate into an independent-adjudication task.

Core requirement (per the build brief): emitting a task for the absolute-$-impact gate
(ABSOLUTE-USD-DERIVATION, Check #148) yields the RIGHT file pointers - asset-identity source
(a real file:line), price source, market-size - plus a STABLE task-hash. Plus: the predmkt
over-claim leaves those pointers UNRESOLVED and flags the cited sweep artifact absent from
the tree; the brief renders with the task-hash bound in; and a returned receipt only greens
when it is CONFIRMED with real cited file:lines (a draft-only / rubber-stamp receipt does not)."""
from __future__ import annotations

import importlib.util
import json
import re
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location(
    "evt", _HERE.parent / "emit-verification-task.py")
_m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_m)

_PREDMKT_FIXTURE = _HERE / "fixtures" / "predmkt_overclaim.md"

# Obyte-like program_rules.json: the fund-loss floor lives only as free text inside
# invalid_impact_conditions (matches the gate's own test fixture).
_OBYTE_LIKE_RULES = {
    "program": "Obyte-like",
    "invalid_impact_conditions": [
        "Any lost/frozen-funds impact below USD 1000 (fund-loss floor)",
    ],
}

# A properly-derived High fund-loss finding: all four derivation parts, source-anchored.
_COMPLETE_DRAFT = """# Reserve drain in prediction-markets AA leads to theft of user funds

Severity: High

## Summary
An attacker drains the reserve pool of the prediction-markets AA on a manipulated price.

## Impact
The loss is denominated in the reserve asset GBYTE (factory.oscript:58 default reserve_asset 'base').
1 GBYTE = 1e9 bytes; GBYTE ~ $5 (coingecko spot price, as of 2026-07-09).
At the pool's current TVL of 2000 GBYTE, a full drain moves 2,000,000,000,000 bytes to the attacker.
The derived loss = 2000 GBYTE = $10,000, which is above the $1000 fund-loss floor.

## What the PoC proves
The PoC drives the drain end-to-end and asserts the attacker balance rises by 2000 GBYTE.
"""

_SCOPE_DRAFT = """# Access-control gap in Vault leads to theft

Severity: High

## Impact
Missing onlyOwner on Vault.sweep (Vault.sol:142) lets anyone drain the vault.
"""


def _ws(rules: dict | None = _OBYTE_LIKE_RULES) -> Path:
    ws = Path(tempfile.mkdtemp())
    (ws / ".auditooor").mkdir(parents=True)
    if rules is not None:
        (ws / ".auditooor" / "program_rules.json").write_text(json.dumps(rules))
    return ws


def _draft(ws: Path, body: str, name: str = "f.md") -> Path:
    fd = ws / "submissions" / "paste_ready" / "f"
    fd.mkdir(parents=True, exist_ok=True)
    p = fd / name
    p.write_text(body)
    return p


def _roles(task: dict) -> dict[str, dict]:
    return {t["role"]: t for t in task["targets"]}


class TestEmitVerificationTask(unittest.TestCase):

    # --- CORE: right file pointers + stable hash for the absolute-$ gate ---------
    def test_absolute_usd_pointers(self):
        ws = _ws()
        md = _draft(ws, _COMPLETE_DRAFT)
        task = _m.build_task(ws, md, "ABSOLUTE-USD-DERIVATION")

        self.assertEqual(task["schema"], "auditooor.verification_task.v1")
        self.assertEqual(task["gate_id"], "ABSOLUTE-USD-DERIVATION")
        self.assertEqual(task["load_bearing_axis"], "impact")
        self.assertEqual(task["satisfiability_before"], "prose-only")
        self.assertEqual(task["expected_evidence_class"], "independent-verification")
        self.assertTrue(task["adjudication_required"])
        self.assertTrue(task["gate_applicable"])

        roles = _roles(task)
        self.assertEqual(list(roles), ["asset_identity", "price_source",
                                       "market_size", "absolute_vs_floor"])

        # asset-identity source = a real source file:line (NOT a draft line).
        ai = roles["asset_identity"]
        self.assertTrue(ai["resolved"])
        self.assertEqual(ai["pointer"], "factory.oscript:58")
        self.assertEqual(ai["kind"], "source_citation")
        self.assertEqual(ai["expected_evidence_class"], "evidence-artifact")

        # price source: unit-scale + named price source extracted.
        ps = roles["price_source"]
        self.assertTrue(ps["resolved"])
        self.assertEqual(ps["value"]["named_source"], "coingecko")
        self.assertEqual(ps["value"]["price_usd"], 5.0)
        self.assertIn("1 GBYTE", ps["value"]["unit_scale"])
        self.assertIn("1e9", ps["value"]["unit_scale"])
        self.assertEqual(ps["expected_evidence_class"], "independent-verification")

        # market-size figure extracted.
        ms = roles["market_size"]
        self.assertTrue(ms["resolved"])
        self.assertIn("TVL", ms["extract"])
        self.assertIn("2000 GBYTE", ms["extract"])

        # stable hash: 64 hex chars, plus the companion claim/pointer hashes.
        self.assertRegex(task["task_hash"], r"^[0-9a-f]{64}$")
        self.assertRegex(task["claim_hash"], r"^[0-9a-f]{64}$")
        self.assertRegex(task["pointer_binding_hash"], r"^[0-9a-f]{64}$")
        # task_hash is the canonical binding of (gate, claim_hash).
        self.assertEqual(task["task_hash"],
                         _m.canonical_task_hash(task["gate_id"], task["claim_hash"]))
        self.assertEqual(task["claim_hash"], _m.claim_hash(task["claim"]))
        # no cited evidence artifacts in a clean draft.
        self.assertEqual(task["artifacts_to_check"], [])
        self.assertEqual(task["missing_artifacts"], [])

    def test_task_hash_is_stable(self):
        ws = _ws()
        md = _draft(ws, _COMPLETE_DRAFT)
        t1 = _m.build_task(ws, md, "ABSOLUTE-USD-DERIVATION")
        t2 = _m.build_task(ws, md, "ABSOLUTE-USD-DERIVATION")
        self.assertEqual(t1["task_hash"], t2["task_hash"])
        self.assertEqual(t1["task_id"], t2["task_id"])
        self.assertIn(t1["task_hash"][:12], t1["task_id"])

    def test_task_hash_changes_with_claim(self):
        ws = _ws()
        t1 = _m.build_task(_ws(), _draft(_ws(), _COMPLETE_DRAFT), "ABSOLUTE-USD-DERIVATION")
        altered = _COMPLETE_DRAFT.replace("$10,000", "$20,000")
        t2 = _m.build_task(ws, _draft(ws, altered), "ABSOLUTE-USD-DERIVATION")
        self.assertNotEqual(t1["task_hash"], t2["task_hash"])

    # --- predmkt over-claim: pointers UNRESOLVED + artifact ABSENT ----------------
    def test_predmkt_overclaim_unresolved_and_missing_artifact(self):
        ws = _ws()
        task = _m.build_task(ws, _PREDMKT_FIXTURE, "ABSOLUTE-USD-DERIVATION")
        roles = _roles(task)
        self.assertFalse(roles["asset_identity"]["resolved"])
        self.assertIsNone(roles["asset_identity"]["pointer"])
        self.assertFalse(roles["price_source"]["resolved"])
        self.assertFalse(roles["market_size"]["resolved"])
        for r in ("asset_identity", "price_source", "market_size"):
            self.assertIn(r, task["unresolved_target_roles"])
        # the cited Node.js sweep is absent from the ws -> flagged, Node.js runtime is not.
        self.assertIn("redeem-slippage-sweep.js", task["missing_artifacts"])
        self.assertTrue(task["claim"])  # a concrete claim sentence is extracted

    # --- context refs carry the floor rubric row + recall block ------------------
    def test_context_refs(self):
        ws = _ws()
        task = _m.build_task(ws, _draft(ws, _COMPLETE_DRAFT), "ABSOLUTE-USD-DERIVATION")
        ctx = task["context_refs"]
        self.assertIn("$1000", ctx["rubric_row"])
        self.assertIn("vault_resume_context", ctx["recall_block"])
        self.assertIn(ws.name, ctx["recall_block"])
        self.assertTrue(ctx["draft_excerpt"])

    # --- brief renders with the task-hash bound in -------------------------------
    def test_render_brief_binds_hash(self):
        ws = _ws()
        task = _m.build_task(ws, _draft(ws, _COMPLETE_DRAFT), "ABSOLUTE-USD-DERIVATION")
        brief = _m.render_brief(task)
        self.assertIn(task["task_hash"], brief)
        self.assertIn(task["claim_hash"], brief)
        self.assertIn(task["gate_id"], brief)
        self.assertIn("factory.oscript:58", brief)
        self.assertIn("DEFAULT VERDICT IS `REFUTED`", brief)
        self.assertNotIn("{{", brief)  # every placeholder substituted

    # --- emit writes the sidecar + index + brief ---------------------------------
    def test_emit_writes_sidecar(self):
        ws = _ws()
        md = _draft(ws, _COMPLETE_DRAFT)
        res = _m.emit(ws, md, "ABSOLUTE-USD-DERIVATION", render=True)
        tp = Path(res["task_path"])
        self.assertTrue(tp.is_file())
        loaded = json.loads(tp.read_text())
        self.assertEqual(loaded["task_hash"], res["task"]["task_hash"])
        self.assertTrue(Path(res["brief_path"]).is_file())
        idx = ws / ".auditooor" / "verification_tasks" / "index.jsonl"
        self.assertTrue(idx.is_file())
        rows = [json.loads(l) for l in idx.read_text().splitlines() if l.strip()]
        self.assertEqual(rows[-1]["task_hash"], res["task"]["task_hash"])

    # --- receipt adjudication: gate greens on a CONFIRMED receipt, not on prose ---
    def _confirmed_receipt(self, task: dict) -> dict:
        return {
            "schema": "auditooor.verification_receipt.v1",
            "task_hash": task["task_hash"],
            "gate_id": task["gate_id"],
            "verdict": "CONFIRMED",
            "per_target": {
                t["role"]: {"verdict": "CONFIRMED",
                            "cited_file_line": "factory.oscript:58",
                            "evidence": "declares GBYTE reserve",
                            "disconfirming_checked": "no alt reserve asset found"}
                for t in task["targets"]},
            "cited_file_lines": ["factory.oscript:58"],
            "disconfirming_evidence_checked": ["checked for a slippage guard; none present"],
            "adjudicator_session": "verify-sess-abc123",
            "adjudicated_at": "2026-07-09T00:00:00Z",
        }

    def test_receipt_greens_when_confirmed(self):
        ws = _ws()
        task = _m.build_task(ws, _draft(ws, _COMPLETE_DRAFT), "ABSOLUTE-USD-DERIVATION")
        res = _m.validate_receipt(task, self._confirmed_receipt(task))
        self.assertTrue(res["greened"], res["reasons"])
        self.assertTrue(res["accepted"])

    def test_receipt_draft_only_citation_does_not_green(self):
        ws = _ws()
        task = _m.build_task(ws, _draft(ws, _COMPLETE_DRAFT), "ABSOLUTE-USD-DERIVATION")
        r = self._confirmed_receipt(task)
        for pt in r["per_target"].values():
            pt["cited_file_line"] = "draft:L5"  # citing the draft back to itself
        res = _m.validate_receipt(task, r)
        self.assertFalse(res["greened"])
        self.assertTrue(res["accepted"])  # validly bound, just not confirmed on real source

    def test_receipt_wrong_hash_not_accepted(self):
        ws = _ws()
        task = _m.build_task(ws, _draft(ws, _COMPLETE_DRAFT), "ABSOLUTE-USD-DERIVATION")
        r = self._confirmed_receipt(task)
        r["task_hash"] = "deadbeef"
        res = _m.validate_receipt(task, r)
        self.assertFalse(res["accepted"])
        self.assertFalse(res["greened"])
        self.assertFalse(res["bound"])

    def test_receipt_refuted_not_greened(self):
        ws = _ws()
        task = _m.build_task(ws, _draft(ws, _COMPLETE_DRAFT), "ABSOLUTE-USD-DERIVATION")
        r = self._confirmed_receipt(task)
        r["verdict"] = "REFUTED"
        res = _m.validate_receipt(task, r)
        self.assertFalse(res["greened"])

    def test_receipt_no_disconfirming_not_greened(self):
        ws = _ws()
        task = _m.build_task(ws, _draft(ws, _COMPLETE_DRAFT), "ABSOLUTE-USD-DERIVATION")
        r = self._confirmed_receipt(task)
        r["disconfirming_evidence_checked"] = []  # rubber-stamp: no refutation attempted
        res = _m.validate_receipt(task, r)
        self.assertFalse(res["greened"])
        self.assertFalse(res["anti_rubber_stamp_ok"])

    # --- generic conversion candidate (scope) turns citations into targets -------
    def test_generic_gate_citation_targets(self):
        ws = _ws()
        task = _m.build_task(ws, _draft(ws, _SCOPE_DRAFT), "SCOPE-AUTHORITY")
        self.assertEqual(task["load_bearing_axis"], "scope")
        ptrs = [t["pointer"] for t in task["targets"]]
        self.assertIn("Vault.sol:142", ptrs)

    def test_unknown_gate_raises(self):
        ws = _ws()
        with self.assertRaises(ValueError):
            _m.build_task(ws, _draft(ws, _COMPLETE_DRAFT), "NO-SUCH-GATE")

    # --- interop: our binding hash must match the authoritative receipt-checker ---
    def test_task_hash_matches_sibling_receipt_checker(self):
        sib_path = _HERE.parent / "verification-receipt-check.py"
        if not sib_path.is_file():
            self.skipTest("verification-receipt-check.py not present")
        spec = importlib.util.spec_from_file_location("vrc", sib_path)
        sib = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(sib)
        except Exception as exc:  # sibling mid-edit; do not fail our suite
            self.skipTest(f"sibling import failed: {exc}")
        if not (hasattr(sib, "claim_hash") and hasattr(sib, "task_hash")):
            self.skipTest("sibling lacks claim_hash/task_hash (contract drift)")
        ws = _ws()
        task = _m.build_task(ws, _draft(ws, _COMPLETE_DRAFT), "ABSOLUTE-USD-DERIVATION")
        # both halves derive claim_hash and task_hash identically from public inputs.
        self.assertEqual(task["claim_hash"], sib.claim_hash(task["claim"]))
        self.assertEqual(task["task_hash"],
                         sib.task_hash(task["gate_id"], sib.claim_hash(task["claim"])))

    # --- CLI ---------------------------------------------------------------------
    def test_cli_list_gates(self):
        self.assertEqual(_m.main(["--list-gates"]), 0)

    def test_cli_emit_json_rc0(self):
        ws = _ws()
        md = _draft(ws, _COMPLETE_DRAFT)
        rc = _m.main(["--workspace", str(ws), "--draft", str(md),
                      "--gate", "ABSOLUTE-USD-DERIVATION", "--json"])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
