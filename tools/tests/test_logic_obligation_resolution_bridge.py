"""Regression: logic-obligation-resolution-bridge produces the resolution sidecar
ONLY for obligations with a genuine source-cited terminal verdict for their own key;
un-adjudicated obligations stay OPEN (no fabrication)."""
import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest

_TOOL = pathlib.Path(__file__).resolve().parent.parent / "logic-obligation-resolution-bridge.py"


def _load():
    spec = importlib.util.spec_from_file_location("_lorb_under_test", _TOOL)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_lorb_under_test"] = mod
    spec.loader.exec_module(mod)
    return mod


class TestLogicObligationResolutionBridge(unittest.TestCase):
    def _ws(self):
        d = pathlib.Path(tempfile.mkdtemp())
        aud = d / ".auditooor"
        (aud / "agent_mechanism_verdicts").mkdir(parents=True)
        # genuine source-cited terminal verdict for SwapIn
        (aud / "agent_mechanism_verdicts" / "v.json").write_text(json.dumps({
            "function": "SwapIn", "contract": "Keeper", "verdict": "REFUTED",
            "impact": "oracle-spot-price-manipulation",
            "file_line": "src/vault/keeper/vault.go:250"}))
        # dataflow substrate so the check is not fail-open
        (aud / "dataflow_paths.jsonl").write_text('{"x":1}\n')
        # one obligation ledger with a MATCHING obligation + a NON-matching one
        (aud / "oracle_spot_price_obligations.jsonl").write_text(
            json.dumps({"function": "SwapIn", "contract": "Keeper",
                        "attack_class": "oracle-spot-price-manipulation",
                        "proof_status": "open"}) + "\n" +
            json.dumps({"function": "TotallyUnadjudicated", "contract": "Keeper",
                        "attack_class": "oracle-spot-price-manipulation",
                        "proof_status": "open"}) + "\n")
        return d

    def test_emits_only_for_genuine_match(self):
        m = _load()
        d = self._ws()
        r = m.bridge(d, apply=True)
        self.assertGreaterEqual(r["emitted"], 1, "the SwapIn obligation must be resolved")
        side = [json.loads(l) for l in
                (d / ".auditooor" / "logic_obligation_resolutions.jsonl").read_text().splitlines() if l.strip()]
        fns = {row.get("function") for row in side}
        self.assertIn("SwapIn", fns)
        self.assertNotIn("TotallyUnadjudicated", fns,
                         "an obligation with no terminal evidence must stay OPEN (no fabrication)")
        for row in side:
            self.assertTrue(m._R76.search(row["evidence_ref"]),
                            "every resolution must carry a source-cited evidence ref")

    def test_no_evidence_emits_nothing(self):
        m = _load()
        d = self._ws()
        # wipe the verdict -> no evidence -> nothing resolvable
        (d / ".auditooor" / "agent_mechanism_verdicts" / "v.json").write_text('{"verdict":"open"}')
        r = m.bridge(d, apply=True)
        self.assertEqual(r["emitted"], 0)


if __name__ == "__main__":
    unittest.main()


class TestReasoningCiteFallback(unittest.TestCase):
    """Regression: a terminal verdict that cites its guard file:line ONLY in the
    reasoning prose (not structured file_line/source_refs - a recurring worker
    foot-gun) must still credit via the reasoning R76 fallback; a cite-less verdict
    must NOT credit. Root-caused 2026-07-14 (axelar epoch verdicts, file_line=None)."""
    def _mod(self):
        import importlib.util, pathlib
        t = pathlib.Path(__file__).resolve().parent.parent / "logic-obligation-resolution-bridge.py"
        spec = importlib.util.spec_from_file_location("eqb_rc", t)
        m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
    def _ws(self, verdict):
        import json, pathlib, tempfile
        d = pathlib.Path(tempfile.mkdtemp()); (d/".auditooor"/"agent_mechanism_verdicts").mkdir(parents=True)
        (d/".auditooor"/"agent_mechanism_verdicts"/"v.json").write_text(json.dumps(verdict))
        return d
    def test_reasoning_cite_credits(self):
        import importlib.util, pathlib, sys
        lspec = importlib.util.spec_from_file_location("_lor_rc", pathlib.Path(__file__).resolve().parent.parent/"logic-obligation-resolution-check.py")
        lm = importlib.util.module_from_spec(lspec); sys.modules["_lor_rc"]=lm; lspec.loader.exec_module(lm)
        m = self._mod()
        d = self._ws({"function":"AddSig","verdict":"refuted","reasoning":"deduped at src/x/multisig/types/signing.go:118 already-submitted"})
        ev = m.build_evidence_index(d, lm)
        self.assertTrue(any("addsig" in k for k in ev), ev)
    def test_citeless_verdict_not_credited(self):
        import importlib.util, pathlib, sys
        lspec = importlib.util.spec_from_file_location("_lor_rc2", pathlib.Path(__file__).resolve().parent.parent/"logic-obligation-resolution-check.py")
        lm = importlib.util.module_from_spec(lspec); sys.modules["_lor_rc2"]=lm; lspec.loader.exec_module(lm)
        m = self._mod()
        d = self._ws({"function":"X","verdict":"refuted","reasoning":"no cite here just prose"})
        self.assertEqual(m.build_evidence_index(d, lm), {})


class TestTypedProofQueueEvidence(unittest.TestCase):
    def _typed_queue(self, mod, exact_terminal):
        parent = ["zdo-logic-bridge", "zdr-logic-bridge"]
        row = {
            "lead_id": "zdpq-logic-bridge",
            "obligation_id": parent[0],
            "revision_id": parent[1],
            "function": "TypedSwapIn",
            "contract": "Keeper",
            "attack_class": "oracle-spot-price-manipulation",
            "proof_status": "disproved",
            "zero_day_proof_projection": {
                "schema": "auditooor.zero_day_proof_queue_projection.v1",
                "freeze_receipt_id": "a" * 64,
                "freeze_input_fingerprint": "b" * 64,
                "obligation_source_row_sha256": "c" * 64,
                "parent_ids": parent,
                "selection_ordinal": 1,
                "question_evidence": [{"question_id": "q0", "axis": "asset_invariant"}],
            },
            "zero_day_proof_admission": {
                "freeze_receipt_id": "a" * 64,
                "input_fingerprint": "b" * 64,
                "obligation_source_row_sha256": "c" * 64,
                "parent_ids": parent,
            },
        }
        payload = {
            "schema": "auditooor.exploit_queue.v1",
            "queue": [row],
            "entries": [],
            "zero_day_proof_admission": {
                "schema": "auditooor.zero_day_proof_admission.v1",
                "admission_id": "zdpa_" + "d" * 64,
                "input_queue_sha256": "e" * 64,
                "freeze_receipt_id": "a" * 64,
                "freeze_input_fingerprint": "b" * 64,
                "admitted_count": 1,
                "admitted_parents": [{"obligation_id": parent[0], "revision_id": parent[1]}],
            },
        }
        if exact_terminal:
            entry = mod._load_typed_envelope_tool().build_envelope(payload)["entries"][0]
            row["terminal_join"] = {
                "schema": "auditooor.zero_day_proof_terminal_verdict.v1",
                "parent_ids": entry["parent_ids"],
                "envelope_id": entry["envelope_id"],
                "evidence_ref": "src/vault/keeper/typed.go:42",
            }
        return payload

    def _evidence(self, exact_terminal):
        mod = _load()
        ws = pathlib.Path(tempfile.mkdtemp())
        aud = ws / ".auditooor"
        aud.mkdir()
        (aud / "exploit_queue.zero_day_admitted.json").write_text(
            json.dumps(self._typed_queue(mod, exact_terminal))
        )
        return mod.build_evidence_index(ws, mod._load_check_module())

    def test_typed_bare_status_cannot_resolve_a_reasoner_obligation(self):
        evidence = self._evidence(exact_terminal=False)
        self.assertFalse(any("typedswapin" in key for key in evidence), evidence)

    def test_typed_exact_terminal_record_supplies_resolution_evidence(self):
        evidence = self._evidence(exact_terminal=True)
        self.assertTrue(any("typedswapin" in key for key in evidence), evidence)
