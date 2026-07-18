# <!-- r36-rebuttal: lane anchor-lead-to-hunt-task registered via agent-pathspec-register.py -->
"""anchor-lead-to-hunt-task: the missing downstream consumer of anchor_leads.jsonl
(commit-anchor-lead-emit.py emits leads that nothing reads; this tool turns each
lead with >=1 in-scope sibling into a scoped hunt task, JSONL-persisted)."""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "anchor-lead-to-hunt-task.py"


def _load():
    spec = importlib.util.spec_from_file_location("anchor_lead_to_hunt_task", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["anchor_lead_to_hunt_task"] = m
    spec.loader.exec_module(m)
    return m


MOD = _load()


def _write_jsonl(path: Path, rows):
    path.write_text("\n".join(json.dumps(r) for r in rows) + ("\n" if rows else ""),
                     encoding="utf-8")


class EmitTest(unittest.TestCase):
    def setUp(self):
        self.ws = Path(tempfile.mkdtemp())
        (self.ws / ".auditooor").mkdir()

    def _inscope(self, rows):
        _write_jsonl(self.ws / ".auditooor" / "inscope_units.jsonl", rows)

    def _leads(self, rows):
        _write_jsonl(self.ws / ".auditooor" / "anchor_leads.jsonl", rows)

    def test_no_leads_file_emits_nothing(self):
        r = MOD.emit(self.ws)
        self.assertEqual(r["leads_read"], 0)
        self.assertEqual(r["tasks_emitted"], 0)
        self.assertFalse((self.ws / ".auditooor" / "anchor_hunt_tasks.jsonl").is_file())

    def test_bare_lead_no_sibling_emits_no_task(self):
        self._leads([{"anchor_sha": "deadbeef", "oos_file": "contracts/x/Foo.sol",
                       "in_scope_siblings": [], "hint": "some fix"}])
        r = MOD.emit(self.ws)
        self.assertEqual(r["leads_read"], 1)
        self.assertEqual(r["leads_with_siblings"], 0)
        self.assertEqual(r["leads_bare"], 1)
        self.assertEqual(r["tasks_emitted"], 0)
        self.assertFalse((self.ws / ".auditooor" / "anchor_hunt_tasks.jsonl").is_file())

    def test_three_strata_style_leads_emit_expected_task_count(self):
        # Mirrors the real strata anchor_leads.jsonl fixture shape: 3 leads,
        # each with 2 in-scope siblings (Accounting.sol, AccountingLib.sol) ->
        # 6 hunt tasks total (one per lead x sibling pair).
        self._inscope([
            {"file": "src/contracts/contracts/tranches/Accounting.sol",
             "function": "setValuationPrice",
             "file_line": "src/contracts/contracts/tranches/Accounting.sol:596",
             "lang": "solidity"},
            {"file": "src/contracts/contracts/tranches/Accounting.sol",
             "function": "calcEffectiveNav",
             "file_line": "src/contracts/contracts/tranches/Accounting.sol:617",
             "lang": "solidity"},
            {"file": "src/contracts/contracts/tranches/utils/AccountingLib.sol",
             "function": "splitValuatedNavOut",
             "file_line": "src/contracts/contracts/tranches/utils/AccountingLib.sol:22",
             "lang": "solidity"},
        ])
        self._leads([
            {"anchor_sha": "d454eb22fdbb37c719dfadd95074d484053cee6f",
             "oos_file": "contracts/tranches/DYSAccounting.sol",
             "in_scope_siblings": [
                 {"in_scope_file": "Accounting.sol", "match": "name-stem:accounting"},
                 {"in_scope_file": "AccountingLib.sol", "match": "name-stem:accounting"},
             ],
             "hint": "fix (DYSAccounting) track srtProjectPnLTime and navTimeNet"},
            {"anchor_sha": "874a80efa5b458f048cc6ab8fbe48e0837012de1",
             "oos_file": "contracts/tranches/DYSAccounting.sol",
             "in_scope_siblings": [
                 {"in_scope_file": "Accounting.sol", "match": "name-stem:accounting"},
                 {"in_scope_file": "AccountingLib.sol", "match": "name-stem:accounting"},
             ],
             "hint": "chore (DYSAccounting): add nav-loss grace period documentation"},
            {"anchor_sha": "97591e308f9a51929e96b7585fe3761008c42078",
             "oos_file": "contracts/tranches/DiscreteAccounting.sol",
             "in_scope_siblings": [
                 {"in_scope_file": "Accounting.sol", "match": "name-stem:accounting"},
                 {"in_scope_file": "AccountingLib.sol", "match": "name-stem:accounting"},
             ],
             "hint": "fix(Accounting): allow riskPremium = 100% (< to <=)"},
        ])
        r = MOD.emit(self.ws)
        self.assertEqual(r["leads_read"], 3)
        self.assertEqual(r["leads_with_siblings"], 3)
        self.assertEqual(r["leads_bare"], 0)
        self.assertEqual(r["tasks_emitted"], 6)

        out_path = self.ws / ".auditooor" / "anchor_hunt_tasks.jsonl"
        self.assertTrue(out_path.is_file())
        lines = [json.loads(l) for l in out_path.read_text(encoding="utf-8").splitlines() if l]
        self.assertEqual(len(lines), 6)

        # every task carries the schema + required fields
        for t in lines:
            self.assertEqual(t["schema_version"], "auditooor.anchor_hunt_task.v1")
            self.assertEqual(t["task_type"], "anchor_lead_hunt_v1")
            self.assertTrue(t["task_id"].startswith("anchorhunt_"))
            self.assertIn(t["anchor_sha"], {
                "d454eb22fdbb37c719dfadd95074d484053cee6f",
                "874a80efa5b458f048cc6ab8fbe48e0837012de1",
                "97591e308f9a51929e96b7585fe3761008c42078",
            })
            self.assertIn(t["oos_file"], {"contracts/tranches/DYSAccounting.sol",
                                           "contracts/tranches/DiscreteAccounting.sol"})
            self.assertIn(t["in_scope_sibling"], {"Accounting.sol", "AccountingLib.sol"})
            self.assertIn(t["hint"], {
                "fix (DYSAccounting) track srtProjectPnLTime and navTimeNet",
                "chore (DYSAccounting): add nav-loss grace period documentation",
                "fix(Accounting): allow riskPremium = 100% (< to <=)",
            })
            self.assertIn(t["anchor_sha"], t["prompt"])
            self.assertIn(t["in_scope_sibling"], t["prompt"])

        # the Accounting.sol tasks carry its 2 resolved function anchors;
        # the AccountingLib.sol tasks carry its 1
        acc_tasks = [t for t in lines if t["in_scope_sibling"] == "Accounting.sol"]
        lib_tasks = [t for t in lines if t["in_scope_sibling"] == "AccountingLib.sol"]
        self.assertEqual(len(acc_tasks), 3)
        self.assertEqual(len(lib_tasks), 3)
        for t in acc_tasks:
            fns = {u["function"] for u in t["candidate_anchors"]}
            self.assertEqual(fns, {"setValuationPrice", "calcEffectiveNav"})
        for t in lib_tasks:
            fns = {u["function"] for u in t["candidate_anchors"]}
            self.assertEqual(fns, {"splitValuatedNavOut"})

    def test_sibling_with_no_matching_inscope_units_still_emits_task_with_empty_anchors(self):
        # inscope_units.jsonl absent/empty -> sibling resolved by the emitter but
        # this tool cannot expand function anchors; task still emitted (bare
        # candidate_anchors), since the FILE-level sibling is itself actionable.
        self._leads([{"anchor_sha": "abc123", "oos_file": "contracts/x/Foo.sol",
                       "in_scope_siblings": [{"in_scope_file": "Bar.sol", "match": "name-stem:foo"}],
                       "hint": "fix bar"}])
        r = MOD.emit(self.ws)
        self.assertEqual(r["tasks_emitted"], 1)
        t = r["tasks"][0]
        self.assertEqual(t["candidate_anchors"], [])
        self.assertEqual(t["in_scope_sibling"], "Bar.sol")

    def test_malformed_lead_lines_are_skipped(self):
        p = self.ws / ".auditooor" / "anchor_leads.jsonl"
        p.write_text(
            "not json\n"
            + json.dumps({"anchor_sha": "s1", "oos_file": "f.sol",
                           "in_scope_siblings": [{"in_scope_file": "g.sol", "match": "x"}]}) + "\n"
            + json.dumps({"no_sha_field": True}) + "\n",
            encoding="utf-8")
        leads = MOD.load_leads(self.ws)
        self.assertEqual(len(leads), 1)
        self.assertEqual(leads[0]["anchor_sha"], "s1")

    def test_max_units_per_sibling_cap(self):
        rows = [
            {"file": "src/Big.sol", "function": f"fn{i}",
             "file_line": f"src/Big.sol:{i}", "lang": "solidity"}
            for i in range(50)
        ]
        self._inscope(rows)
        self._leads([{"anchor_sha": "cap1", "oos_file": "contracts/x/OosBig.sol",
                       "in_scope_siblings": [{"in_scope_file": "Big.sol", "match": "name-stem:big"}],
                       "hint": "h"}])
        r = MOD.emit(self.ws)
        self.assertEqual(r["tasks_emitted"], 1)
        self.assertLessEqual(len(r["tasks"][0]["candidate_anchors"]), MOD.MAX_UNITS_PER_SIBLING)


class RealStrataFixtureTest(unittest.TestCase):
    """End-to-end proof against the REAL strata workspace artifact, if present
    on this machine (skips gracefully in a clean CI checkout that lacks the
    workspace tree)."""

    def test_real_strata_workspace_round_trip(self):
        ws = Path.home() / "audits" / "strata"
        leads_path = ws / ".auditooor" / "anchor_leads.jsonl"
        if not leads_path.is_file():
            self.skipTest("no real strata workspace on this machine")
        r = MOD.emit(ws)
        self.assertGreaterEqual(r["leads_read"], 1)
        self.assertGreaterEqual(r["tasks_emitted"], 1)
        for t in r["tasks"]:
            self.assertEqual(t["schema_version"], "auditooor.anchor_hunt_task.v1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
