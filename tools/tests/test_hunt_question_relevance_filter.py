#!/usr/bin/env python3
"""Regression test for hunt-question-relevance-filter.py.

Drops a per-fn hunt task ONLY when its question leans on OOS-protocol class terms
(lending/AMM/oracle/rollup/Monero/...) that have no surface in the in-scope source.
Conservative: a question with no class term, or whose class term is present in scope,
is KEPT (R76 recall-floor - never silently drop a possibly-real lead). Surfaced on
near-intents 2026-06-26: 145 dispatched tasks, 0 applicable, the corpus floods a bridge
target with DeFi templates.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "hunt-question-relevance-filter.py"
_spec = importlib.util.spec_from_file_location("hqrf", _TOOL)
hqrf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hqrf)


def _task(hyp_text):
    return {"task_id": "t", "prompt": f"preamble...\nHYPOTHESIS (source: q-1):\n{hyp_text}\n=== NEXT ==="}


class RelevanceTest(unittest.TestCase):
    # a bridge/MPC source corpus: has bridge/transfer/nonce/signature, NO lending/amm/rollup
    CORPUS = ("fn fin_transfer() { completed_transfers.insert(nonce); verify_proof(); } "
              "fn ecdsa_recover() {} struct domainseparator; merkle_root proof").lower()

    def test_drops_lending_class_absent(self):
        r = hqrf.relevance(_task("Can totalDebt be inflated so liquidation under-collateralizes?"), self.CORPUS)
        self.assertEqual(r["verdict"], "irrelevant")
        self.assertIn("totaldebt", r["class_terms"])

    def test_drops_rollup_class_absent(self):
        r = hqrf.relevance(_task("Does the validatorSet bitField allow a forged assertion?"), self.CORPUS)
        self.assertEqual(r["verdict"], "irrelevant")

    def test_drops_oracle_class_absent(self):
        r = hqrf.relevance(_task("Is latestRoundData used as a spot price enabling a twap manipulation?"), self.CORPUS)
        self.assertEqual(r["verdict"], "irrelevant")

    def test_keeps_bridge_question_no_class_term(self):
        # a genuine bridge replay/binding question has no OOS class term -> fail-open KEEP
        r = hqrf.relevance(_task("Does fin_transfer verify each claimed source-chain export tx id, or accept a forged nonce?"), self.CORPUS)
        self.assertEqual(r["verdict"], "keep")

    def test_keeps_when_class_term_present_in_scope(self):
        corpus = self.CORPUS + " fn liquidate_position() {}"
        r = hqrf.relevance(_task("Can liquidation be front-run?"), corpus)
        self.assertEqual(r["verdict"], "keep")
        self.assertIn("liquidat", r["present"])

    def test_no_rust_borrow_false_match(self):
        # Rust borrow-checker 'borrow' must NOT be an OOS class term (would false-drop)
        corpus = "let x = data.borrow(); fn fin_transfer(){}".lower()
        r = hqrf.relevance(_task("Does the code borrow the value before checking?"), corpus)
        self.assertEqual(r["verdict"], "keep")  # 'borrow' is not a class term

    def test_empty_question_fails_open(self):
        r = hqrf.relevance({"task_id": "t", "prompt": "no hypothesis block here"}, self.CORPUS)
        self.assertEqual(r["verdict"], "keep")

    def test_end_to_end_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            (ws / "src" / "bridge").mkdir(parents=True)
            (ws / "src" / "bridge" / "lib.rs").write_text(self.CORPUS, encoding="utf-8")
            (ws / "targets.tsv").write_text("url\tpin\tbridge\n", encoding="utf-8")
            batch = Path(tmp) / "b.jsonl"
            batch.write_text(
                json.dumps(_task("liquidation of collateralRatio under totalDebt inflation")) + "\n"
                + json.dumps(_task("Does fin_transfer reject a forged nonce?")) + "\n",
                encoding="utf-8")
            out = Path(tmp) / "keep.jsonl"
            dropped = Path(tmp) / "drop.jsonl"
            rc = hqrf.main(["--workspace", str(ws), "--batch", str(batch),
                            "--out", str(out), "--dropped", str(dropped)])
            self.assertEqual(rc, 0)
            kept = [l for l in out.read_text().splitlines() if l.strip()]
            drop = [l for l in dropped.read_text().splitlines() if l.strip()]
            self.assertEqual(len(kept), 1)   # the bridge question
            self.assertEqual(len(drop), 1)   # the lending question


if __name__ == "__main__":
    unittest.main()
