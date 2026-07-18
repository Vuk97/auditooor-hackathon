# <!-- r36-rebuttal: lane commit-anchor-lead-emit registered via agent-pathspec-register.py -->
"""commit-anchor-lead-emit: under primacy-of-RULES, emit an in-scope anchor-hunt lead
per OOS security-shaped commit (strata 2026-07-02 operator principle - GitHub mining is
free, findings must land in-scope, OOS parallel-impls anchor in-scope hunts)."""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "commit-anchor-lead-emit.py"


def _load():
    spec = importlib.util.spec_from_file_location("commit_anchor_lead_emit", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["commit_anchor_lead_emit"] = m
    spec.loader.exec_module(m)
    return m


MOD = _load()


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)


class HelperTest(unittest.TestCase):
    def test_name_stem_strips_twin_affixes(self):
        self.assertEqual(MOD._name_stem("DYSAccounting.sol"), "accounting")
        self.assertEqual(MOD._name_stem("DiscreteAccounting.sol"), "accounting")
        self.assertEqual(MOD._name_stem("Accounting.sol"), "accounting")
        self.assertEqual(MOD._name_stem("CDOLens.sol"), "cdo")

    def test_bases_of_parses_inheritance(self):
        b = MOD._bases_of("contract DYSAccounting is IAccounting, CDOComponent { }")
        self.assertEqual(b["DYSAccounting"], {"IAccounting", "CDOComponent"})


class EmitTest(unittest.TestCase):
    def setUp(self):
        os.environ.pop("AUDITOOOR_SCOPE_MODE", None)
        self.ws = Path(tempfile.mkdtemp())
        (self.ws / ".auditooor").mkdir()
        (self.ws / "SCOPE.md").write_text("Primacy of RULES. In scope: Accounting.sol.",
                                          encoding="utf-8")
        self.repo = self.ws / "src"
        (self.repo / "tranches").mkdir(parents=True)
        _git(self.repo, "init", "-q"); _git(self.repo, "config", "user.email", "t@t.t")
        _git(self.repo, "config", "user.name", "t")
        # in-scope Accounting + OOS DYSAccounting share IAccounting
        (self.repo / "tranches" / "Accounting.sol").write_text(
            "contract Accounting is IAccounting, CDOComponent { function f() public {} }",
            encoding="utf-8")
        (self.ws / ".auditooor" / "inscope_units.jsonl").write_text(
            json.dumps({"file": "src/tranches/Accounting.sol", "function": "f"}), encoding="utf-8")
        (self.repo / "tranches" / "DYSAccounting.sol").write_text(
            "contract DYSAccounting is IAccounting, CDOComponent { function g() public {} }",
            encoding="utf-8")
        _git(self.repo, "add", "-A"); _git(self.repo, "commit", "-qm", "fix(DYSAccounting): x")
        self.sha = subprocess.run(["git", "-C", str(self.repo), "rev-parse", "HEAD"],
                                  capture_output=True, text=True).stdout.strip()

    def _ledger(self, shas):
        (self.ws / ".auditooor" / "commit_lifecycle_ledger.json").write_text(json.dumps({
            "lanes_residual": [{"classification": "security_shaped_commit", "sha": s, "hint": "h"}
                               for s in shas]}), encoding="utf-8")

    def test_emits_inscope_sibling_lead_for_oos_twin(self):
        self._ledger([self.sha])
        r = MOD.emit(self.ws)
        self.assertEqual(r["scope_mode"], "rules")
        self.assertEqual(r["emitted"], 1)
        lead = r["leads"][0]
        self.assertIn("DYSAccounting.sol", lead["oos_file"])
        sibs = [s["in_scope_file"] for s in lead["in_scope_siblings"]]
        self.assertIn("Accounting.sol", sibs)
        self.assertTrue(any("shared-interface" in s["match"] for s in lead["in_scope_siblings"]))
        # artifact written
        self.assertTrue((self.ws / ".auditooor" / "anchor_leads.jsonl").is_file())

    def test_impact_mode_emits_nothing(self):
        os.environ["AUDITOOOR_SCOPE_MODE"] = "impact"
        try:
            self._ledger([self.sha])
            r = MOD.emit(self.ws)
            self.assertEqual(r["scope_mode"], "impact")
            self.assertEqual(r["emitted"], 0)
        finally:
            os.environ.pop("AUDITOOOR_SCOPE_MODE", None)

    def test_inscope_commit_is_not_an_anchor(self):
        # a commit touching the IN-SCOPE file is the adjudication gate's job, not a lead
        (self.repo / "tranches" / "Accounting.sol").write_text(
            "contract Accounting is IAccounting, CDOComponent { function f() public { } }",
            encoding="utf-8")
        _git(self.repo, "add", "-A"); _git(self.repo, "commit", "-qm", "fix(Accounting): y")
        sha2 = subprocess.run(["git", "-C", str(self.repo), "rev-parse", "HEAD"],
                              capture_output=True, text=True).stdout.strip()
        self._ledger([sha2])
        self.assertEqual(MOD.emit(self.ws)["emitted"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
