"""Focused tests for reasoner-firing-nonvacuity-check.py - the FIRING (non-vacuity)
gate that asserts every wired LOGIC/novelty reasoner examined>0 AND emitted a
recorded result (obligation / cited-empty examined-record / source-cited exemption).
A SILENTLY vacuous reasoner (empty/missing ledger, no record) must FAIL under strict.

Cases: fired (anchored obligation), fired_clean (cited-empty record), exempt (degraded
surface-absent record + operator sidecar), vacuous (empty & missing -> fail under
strict, advisory-pass by default), and the no-auto-exempt guarantee."""
import importlib.util
import json
import os
import pathlib
import sys
import tempfile
import unittest

_TOOL = pathlib.Path(__file__).resolve().parent.parent / "reasoner-firing-nonvacuity-check.py"


def _load():
    spec = importlib.util.spec_from_file_location("_rfnv_under_test", _TOOL)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_rfnv_under_test"] = mod
    spec.loader.exec_module(mod)
    return mod


_M = _load()


def _verdict_for(res, ledger):
    for e in res["per_reasoner"]:
        if e["ledger"] == ledger:
            return e["verdict"]
    raise AssertionError(f"{ledger} not classified (registry drift?)")


class TestReasonerFiring(unittest.TestCase):
    def setUp(self):
        # neutralize any ambient L37 env so default-policy tests are deterministic
        self._saved = {k: os.environ.pop(k, None) for k in (
            "AUDITOOOR_L37_STRICT", "AUDITOOOR_L37_REASONER_FIRING_STRICT")}

    def tearDown(self):
        for k, v in self._saved.items():
            if v is not None:
                os.environ[k] = v
            else:
                os.environ.pop(k, None)

    def _ws(self):
        d = pathlib.Path(tempfile.mkdtemp())
        (d / ".auditooor").mkdir()
        return d

    def test_registry_loads(self):
        led = _M._load_reasoner_ledgers()
        self.assertGreaterEqual(len(led), 30, "should import the ~35-reasoner registry")
        names = {n for n, _, _ in led}
        self.assertIn("numeric_boundary_obligations.jsonl", names)

    def test_fired_anchored_obligation(self):
        d = self._ws()
        (d / ".auditooor" / "numeric_boundary_obligations.jsonl").write_text(
            json.dumps({"contract": "CrossChainManager", "function": "burn",
                        "attack_class": "amount-extremal", "proof_status": "needs_source"}) + "\n")
        r = _M.check(d)
        self.assertEqual(_verdict_for(r, "numeric_boundary_obligations.jsonl"), "fired")

    def test_fired_clean_cited_empty_record(self):
        # ran, examined, RECORDED 0 survivors (not degraded) -> fired_clean PASS
        d = self._ws()
        (d / ".auditooor" / "slice_oob_bounds_taint.jsonl").write_text(
            json.dumps({"schema": "slice_oob_bounds_taint.v1", "survivors": 0,
                        "note": "cited-empty: OOB taint+dominance screen ran, no survivor"}) + "\n")
        r = _M.check(d)
        self.assertEqual(_verdict_for(r, "slice_oob_bounds_taint.jsonl"), "fired_clean")

    def test_exempt_degraded_surface_absent(self):
        # reasoner recorded a degraded run (rust crate absent) -> exempt PASS with reason
        d = self._ws()
        (d / ".auditooor" / "rust_unchecked_arith_obligations.jsonl").write_text(
            json.dumps({"note": "cited-empty: query ran over MIR, no unchecked arith found",
                        "survivors": 0,
                        "report": {"any_mir": False, "degraded": True,
                                   "crates": {"nuva": {"mir_error": "no-cargo-toml",
                                                       "survivors": 0}},
                                   "totals": {"survivors": 0}}}) + "\n")
        r = _M.check(d)
        e = next(x for x in r["per_reasoner"]
                 if x["ledger"] == "rust_unchecked_arith_obligations.jsonl")
        self.assertEqual(e["verdict"], "exempt")
        self.assertIn("no-cargo-toml", e["reason"])

    def test_exempt_operator_sidecar_for_missing(self):
        # a MISSING ledger becomes exempt ONLY with an explicit recorded sidecar row
        d = self._ws()
        (d / ".auditooor" / "reasoner_firing_exemptions.jsonl").write_text(
            json.dumps({"ledger": "zk_constraint_coverage_obligations.jsonl",
                        "reason": "no zk/circuit surface in this workspace",
                        "citation": "SCOPE.md: no *.circom / halo2 crate"}) + "\n")
        r = _M.check(d)
        e = next(x for x in r["per_reasoner"]
                 if x["ledger"] == "zk_constraint_coverage_obligations.jsonl")
        self.assertEqual(e["verdict"], "exempt")
        self.assertIn("no zk", e["reason"])

    def test_vacuous_empty_file_fails_under_strict(self):
        d = self._ws()
        # empty ledger (0 rows) for a reasoner with no exemption == silent vacuity
        (d / ".auditooor" / "push_payment_misroute_obligations.jsonl").write_text("")
        # default policy: advisory WARN-pass
        r_default = _M.check(d)
        self.assertTrue(r_default["ok"])
        self.assertEqual(r_default["verdict"], "pass-advisory-vacuous")
        self.assertIn("push_payment_misroute_obligations.jsonl",
                      r_default["vacuous_ledgers"])
        # strict: fail-closed
        os.environ["AUDITOOOR_L37_REASONER_FIRING_STRICT"] = "1"
        try:
            r_strict = _M.check(d)
        finally:
            os.environ.pop("AUDITOOOR_L37_REASONER_FIRING_STRICT", None)
        self.assertFalse(r_strict["ok"])
        self.assertEqual(r_strict["verdict"], "fail-reasoner-vacuous")

    def test_missing_ledger_is_vacuous_not_auto_exempt(self):
        # THE no-auto-green guarantee: a lang-scoped (zk) ledger that is simply MISSING,
        # with NO recorded exemption, must be VACUOUS - never silently exempted by lang.
        d = self._ws()
        r = _M.check(d)
        self.assertEqual(_verdict_for(r, "zk_constraint_coverage_obligations.jsonl"),
                         "vacuous")

    def test_rows_present_but_no_anchor_no_record_is_vacuous(self):
        d = self._ws()
        (d / ".auditooor" / "atomic_sequence_obligations.jsonl").write_text(
            json.dumps({"schema": "x", "misc": "no anchor, no survivors key, no note"}) + "\n")
        r = _M.check(d)
        self.assertEqual(_verdict_for(r, "atomic_sequence_obligations.jsonl"), "vacuous")

    def test_global_l37_strict_also_enforces(self):
        d = self._ws()
        (d / ".auditooor" / "push_payment_misroute_obligations.jsonl").write_text("")
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        try:
            r = _M.check(d)
        finally:
            os.environ.pop("AUDITOOOR_L37_STRICT", None)
        self.assertFalse(r["ok"])

    def test_per_gate_optout_downgrades_under_global_strict(self):
        d = self._ws()
        (d / ".auditooor" / "push_payment_misroute_obligations.jsonl").write_text("")
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        os.environ["AUDITOOOR_L37_REASONER_FIRING_STRICT"] = "0"  # explicit opt-out
        try:
            r = _M.check(d)
        finally:
            os.environ.pop("AUDITOOOR_L37_STRICT", None)
            os.environ.pop("AUDITOOOR_L37_REASONER_FIRING_STRICT", None)
        self.assertTrue(r["ok"], "explicit per-gate opt-out downgrades to advisory")

    # ---- vacuity CAUSE diagnosis (missing-producer / ordering-staleness /
    #      predicate-mismatch / genuine-na + exemption) ----------------------

    def _cause_for(self, res, ledger):
        for e in res["per_reasoner"]:
            if e["ledger"] == ledger:
                return e["cause"]
        raise AssertionError(f"{ledger} not classified (registry drift?)")

    def _write_substrate(self, ws, mtime=None, rows=1):
        """Write the dataflow substrate the reasoners consume; optional mtime pin."""
        p = ws / ".auditooor" / "dataflow_paths.jsonl"
        p.write_text("".join(
            json.dumps({"path_id": i, "sink": "x"}) + "\n" for i in range(rows)))
        if mtime is not None:
            os.utime(p, (mtime, mtime))
        return p

    def test_cause_missing_producer_no_substrate(self):
        # empty ledger + NO dataflow substrate at all -> missing-producer
        d = self._ws()
        (d / ".auditooor" / "push_payment_misroute_obligations.jsonl").write_text("")
        r = _M.check(d)
        self.assertFalse(r["substrate_present"])
        self.assertEqual(
            self._cause_for(r, "push_payment_misroute_obligations.jsonl"),
            "missing-producer")

    def test_cause_missing_producer_zero_line_substrate(self):
        # a 0-line substrate shard reads as absent -> missing-producer
        d = self._ws()
        (d / ".auditooor" / "dataflow_paths.jsonl").write_text("")  # 0 rows
        (d / ".auditooor" / "push_payment_misroute_obligations.jsonl").write_text("")
        r = _M.check(d)
        self.assertFalse(r["substrate_present"])
        self.assertEqual(
            self._cause_for(r, "push_payment_misroute_obligations.jsonl"),
            "missing-producer")

    def test_cause_ordering_staleness_substrate_newer(self):
        # substrate present + non-empty, but NEWER than the (empty) ledger -> stale
        d = self._ws()
        led = d / ".auditooor" / "push_payment_misroute_obligations.jsonl"
        led.write_text("")
        os.utime(led, (1_000_000, 1_000_000))
        self._write_substrate(d, mtime=2_000_000)  # substrate strictly newer
        r = _M.check(d)
        self.assertTrue(r["substrate_present"])
        self.assertEqual(
            self._cause_for(r, "push_payment_misroute_obligations.jsonl"),
            "ordering-staleness")

    def test_cause_ordering_staleness_missing_ledger_with_substrate(self):
        # substrate present + fresh, ledger MISSING entirely -> ordering-staleness
        d = self._ws()
        self._write_substrate(d, mtime=2_000_000)
        r = _M.check(d)
        self.assertEqual(
            self._cause_for(r, "push_payment_misroute_obligations.jsonl"),
            "ordering-staleness")

    def test_cause_predicate_mismatch_substrate_fresh_zero_rows(self):
        # substrate present + NOT newer than the ledger (reasoner ran the current
        # input) yet emitted 0 rows -> predicate-mismatch
        d = self._ws()
        self._write_substrate(d, mtime=1_000_000)
        led = d / ".auditooor" / "push_payment_misroute_obligations.jsonl"
        led.write_text("")
        os.utime(led, (2_000_000, 2_000_000))  # ledger newer than substrate
        r = _M.check(d)
        self.assertTrue(r["substrate_present"])
        self.assertEqual(
            self._cause_for(r, "push_payment_misroute_obligations.jsonl"),
            "predicate-mismatch")

    def test_cause_genuine_na_for_exempt(self):
        # a RECORDED operator exemption reads as cause=genuine-na, never vacuous
        d = self._ws()
        (d / ".auditooor" / "reasoner_firing_exemptions.jsonl").write_text(
            json.dumps({"ledger": "zk_constraint_coverage_obligations.jsonl",
                        "reason": "no zk/circuit surface",
                        "citation": "SCOPE.md"}) + "\n")
        r = _M.check(d)
        self.assertEqual(
            self._cause_for(r, "zk_constraint_coverage_obligations.jsonl"),
            "genuine-na")

    def test_cause_fired_for_anchored(self):
        d = self._ws()
        (d / ".auditooor" / "numeric_boundary_obligations.jsonl").write_text(
            json.dumps({"contract": "C", "function": "f",
                        "attack_class": "amount-extremal"}) + "\n")
        r = _M.check(d)
        self.assertEqual(
            self._cause_for(r, "numeric_boundary_obligations.jsonl"), "fired")

    def test_cause_counts_aggregate_sums_to_n_reasoners(self):
        d = self._ws()
        r = _M.check(d)
        self.assertEqual(sum(r["cause_counts"].values()), r["n_reasoners"])

    def test_all_fired_or_exempt_passes_clean(self):
        d = self._ws()
        led = _M._load_reasoner_ledgers()
        aud = d / ".auditooor"
        for fname, _tool, _lang in led:
            p = aud / fname
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps({"function": "F", "contract": "C",
                                     "attack_class": "x"}) + "\n")
        os.environ["AUDITOOOR_L37_REASONER_FIRING_STRICT"] = "1"
        try:
            r = _M.check(d)
        finally:
            os.environ.pop("AUDITOOOR_L37_REASONER_FIRING_STRICT", None)
        self.assertTrue(r["ok"])
        self.assertEqual(r["vacuous"], 0)
        self.assertEqual(r["verdict"], "pass")


if __name__ == "__main__":
    unittest.main()
