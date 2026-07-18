"""F1/E1.4: corpus-driven-hunt emit_proof_queue flags a VACUOUS corpus hunt (every
hypothesis need_more_evidence => corpus anchored to no real source in the CUT) so the
pipeline can fail-closed under --strict instead of greening a hollow grounding.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load_cdh():
    spec = importlib.util.spec_from_file_location(
        "corpus_driven_hunt", str(_TOOLS / "corpus-driven-hunt.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["corpus_driven_hunt"] = mod
    spec.loader.exec_module(mod)
    return mod


def _hyp(cdh, inv_id, need_more):
    return cdh.Hypothesis(
        rank=1, score=1.0, invariant_id=inv_id, category="accounting",
        family="accounting_conservation", target_lang="solidity",
        statement="supply conserved", hypothesis="check supply",
        evidence_keywords=["mint", "burn"],
        in_target_evidence=([] if need_more else [{"file": "src/V.sol", "line": 10, "kw": "mint"}]),
        candidate_functions=[{"file_line": "src/V.sol:10", "name": "mint"}],
        corpus_source_ids=["c1"], need_more_evidence=need_more,
        differential_test_idea="mint then assert supply",
    )


class TestF1VacuityGate(unittest.TestCase):
    def setUp(self):
        self.cdh = _load_cdh()
        self.qpath = Path(tempfile.mkdtemp()).resolve() / "exploit_queue.json"

    def test_all_need_more_is_vacuous(self):
        hyps = [_hyp(self.cdh, "INV-A-1", True), _hyp(self.cdh, "INV-A-2", True)]
        out = self.cdh.emit_proof_queue(self.qpath, "ws", hyps, [])
        self.assertTrue(out["vacuous_corpus_hunt"])
        self.assertEqual(out["non_vacuous_hypotheses"], 0)

    def test_one_real_anchor_is_non_vacuous(self):
        hyps = [_hyp(self.cdh, "INV-A-1", True), _hyp(self.cdh, "INV-A-2", False)]
        out = self.cdh.emit_proof_queue(self.qpath, "ws", hyps, [])
        self.assertFalse(out["vacuous_corpus_hunt"])
        self.assertEqual(out["non_vacuous_hypotheses"], 1)

    def test_empty_hyps_not_vacuous_flag(self):
        # no hypotheses at all is a different (no-corpus-match) condition, not the
        # vacuity gate; vacuous requires >=1 hypothesis all need_more_evidence.
        out = self.cdh.emit_proof_queue(self.qpath, "ws", [], [])
        self.assertFalse(out["vacuous_corpus_hunt"])

    def test_queue_grounded_with_inv_ids(self):
        # the whole point of F1: emitted fuel rows carry the INV id so chain-synth
        # can collect them (0 -> N).
        hyps = [_hyp(self.cdh, "INV-A-2", False)]
        self.cdh.emit_proof_queue(self.qpath, "ws", hyps, [])
        data = json.loads(self.qpath.read_text())
        rows = data.get("queue", [])
        fuel = [r for r in rows if r.get("source") == self.cdh.CORPUS_HUNT_FUEL_SOURCE]
        self.assertTrue(fuel, "at least one corpus-hunt-fuel row written")
        self.assertTrue(any(r.get("broken_invariant_ids") for r in fuel),
                        "fuel rows must carry broken_invariant_ids for the chain-synth join")


if __name__ == "__main__":
    unittest.main(verbosity=2)
