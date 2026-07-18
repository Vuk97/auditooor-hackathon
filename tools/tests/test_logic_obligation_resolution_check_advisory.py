"""Regression: logic-obligation-resolution-check must EXCLUDE advisory reasoner rows
(advisory=True / verdict=needs_source: the reasoner's own 'no entrypoint-reachable
impact path' notes) from the blocking OPEN count. Only non-advisory SURVIVOR rows
(a reachable, unguarded path to an impact sink) owe a terminal verdict. Root-caused
2026-07-14 (NUVA: 393 of 549 'open' were advisory needs_source -> false-red)."""
import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest

_TOOL = pathlib.Path(__file__).resolve().parent.parent / "logic-obligation-resolution-check.py"


def _load():
    spec = importlib.util.spec_from_file_location("_lorc_under_test", _TOOL)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_lorc_under_test"] = mod
    spec.loader.exec_module(mod)
    return mod


_M = _load()


class TestAdvisoryExclusion(unittest.TestCase):
    def _ws(self):
        d = pathlib.Path(tempfile.mkdtemp())
        aud = d / ".auditooor"
        aud.mkdir()
        (aud / "dataflow_paths.jsonl").write_text('{"x":1}\n')
        # the assumption_negation ledger is in _REASONER_LEDGERS
        (aud / "assumption_negation_obligations.jsonl").write_text(
            json.dumps({"verdict": "survivor", "proof_status": "open",
                        "function": "SwapIn", "contract": "Keeper",
                        "attack_class": "novel-assumption-negation"}) + "\n" +
            json.dumps({"verdict": "needs_source", "advisory": True,
                        "proof_status": "open", "function": "", "file": "",
                        "attack_class": "novel-assumption-negation"}) + "\n" +
            json.dumps({"verdict": "needs_source", "advisory": True,
                        "proof_status": "open", "function": "X", "file": "y.go",
                        "attack_class": "novel-assumption-negation"}) + "\n")
        return d

    def test_advisory_rows_excluded_from_open(self):
        d = self._ws()
        r = _M.check(d)
        self.assertEqual(r["open"], 1, "only the 1 survivor is a blocking obligation")
        adv = sum(x.get("advisory", 0) for x in r["per_ledger"])
        self.assertEqual(adv, 2, "both needs_source rows are advisory, not obligations")

    def test_is_advisory_row(self):
        self.assertTrue(_M._is_advisory_row({"advisory": True}))
        self.assertTrue(_M._is_advisory_row({"verdict": "needs_source"}))
        self.assertFalse(_M._is_advisory_row({"verdict": "survivor"}))


if __name__ == "__main__":
    unittest.main()


class TestTerminalNegativeTokens(unittest.TestCase):
    """Regression: terminal-negative verdicts a hunt worker emits interchangeably
    with refuted/killed (NEGATIVE, disproved, not-exploitable) must count as TERMINAL,
    else a genuine source-cited NEGATIVE reads as OPEN. Root-caused 2026-07-14 (NUVA
    freeze/epoch adjudication lanes wrote verdict='NEGATIVE' and stayed uncredited)."""
    def test_negative_family_is_terminal(self):
        for v in ("NEGATIVE", "negative", "disproved", "not-exploitable", "not_exploitable"):
            self.assertTrue(_M._is_terminal_token(v), f"{v} must be terminal")
    def test_open_sentinels_still_open(self):
        for v in ("open", "needs_source", "pending", ""):
            self.assertFalse(_M._is_terminal_token(v), f"{v} must stay open")


class TestCompositionSiteKeys(unittest.TestCase):
    """Regression: composition (op_a/op_b) and site-keyed (dirm) obligations carry no
    function/contract, so _obligation_keys must emit comp:: / site:: composite keys -
    else a bridge resolution row for a genuinely both-ops-terminal composition (or a
    file-terminal dirm residual) can never match. Root-caused 2026-07-14."""
    def test_composition_pair_key(self):
        keys = _M._obligation_keys({"op_a": "triggerRedeem", "op_b": "_doDeposit",
                                    "invariant_id": "cns-inv-1"})
        self.assertTrue(any(k.startswith("comp") for k in keys), keys)
        # order-independent: sorted pair
        keys2 = _M._obligation_keys({"op_a": "_doDeposit", "op_b": "triggerRedeem",
                                     "invariant_id": "cns-inv-1"})
        self.assertEqual([k for k in keys if k.startswith("comp")],
                         [k for k in keys2 if k.startswith("comp")])
    def test_site_key(self):
        keys = _M._obligation_keys({"site": {"file": "/abs/src/vault/keeper/valuation_engine.go",
                                             "line": 208}, "invariant_form": "ratio-authority"})
        self.assertTrue(any(k.startswith("site") and "valuation-engine" in k for k in keys), keys)
    def test_no_keys_for_bare_row(self):
        self.assertEqual(_M._obligation_keys({}), [])


class TestCitedEmptyReportExclusion(unittest.TestCase):
    """Regression: a reasoner's cited-empty / degraded summary report row (ran, found 0
    survivors, or degraded on an absent language/crate) is terminal-clean, NOT an open
    obligation. Root-caused 2026-07-14 (NUVA rust_unchecked_arith degraded no-cargo-toml)."""
    def test_cited_empty_report_is_advisory(self):
        self.assertTrue(_M._is_advisory_row({"note": "cited-empty: query ran over MIR, no unchecked found"}))
    def test_degraded_zero_survivor_report_is_advisory(self):
        self.assertTrue(_M._is_advisory_row({"report": {"degraded": True, "totals": {"survivors": 0}}}))
    def test_anchored_row_not_excluded(self):
        self.assertFalse(_M._is_advisory_row({"function": "SwapIn", "note": "cited-empty"}))
    def test_degraded_with_survivors_not_excluded(self):
        self.assertFalse(_M._is_advisory_row({"report": {"degraded": True, "totals": {"survivors": 3}}}))
