"""Regression: Oscript (LLM-hunt-only, no-engine DSL) value-moving recognition +
hunt-sidecar coverage credit across value-moving-functions.py and
invariant-fuzz-completeness.py.

Capability (Obyte 2026-07-09): a language with NO static/fuzz engine
(is_llm_hunt_only(lang) True, e.g. Obyte Autonomous Agents .oscript / .aa) was
INVISIBLE to both tools - value-moving-functions.py's _EXT_TO_LANG had no oscript
so _lang() returned None and no rows were produced, and invariant-fuzz's
asset-coverage denominator/credit were Solidity-only. The fix:

  value-moving-functions.py
    - seeds DECLARATIVE (manifest-seed) langs from inscope_units.jsonl's
      value_movers/state_writes fields (payment/asset -> transfer_hit;
      state/definition/any state_write -> ledger_write_hit);
    - a pure getter (no value_movers/state_writes) is NOT value-moving;
    - engine langs (sol/go/rs/move/cairo) are NEVER manifest-seeded (byte-identical);
    - default-ON, kill-switch AUDITOOOR_OSCRIPT_VALUE_MOVING=0.

  invariant-fuzz-completeness.py
    - credits an LLM-hunt-only file that carries a genuine hunt verdict
      (a hunt_findings_sidecar anchored to the file with a non-empty
      applies_to_target) as `covered` - NO medusa/echidna campaign is demanded;
    - a value-moving oscript file with NO sidecar stays an (advisory) gap - no over-credit;
    - an ENGINE-language file (.sol/.go/.rs) is NEVER credited via this path;
    - default-ON, kill-switch AUDITOOOR_OSCRIPT_HUNT_COVERAGE=0.
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load(mod_name: str, filename: str):
    spec = importlib.util.spec_from_file_location(mod_name, str(_TOOLS / filename))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


class OscriptLlmHuntCoverageTest(unittest.TestCase):
    def setUp(self):
        self.vmf = _load("vmf_oscript", "value-moving-functions.py")
        self.ifc = _load("ifc_oscript", "invariant-fuzz-completeness.py")
        # keep env clean between tests
        for k in ("AUDITOOOR_OSCRIPT_VALUE_MOVING", "AUDITOOOR_OSCRIPT_HUNT_COVERAGE"):
            os.environ.pop(k, None)

    def tearDown(self):
        for k in ("AUDITOOOR_OSCRIPT_VALUE_MOVING", "AUDITOOOR_OSCRIPT_HUNT_COVERAGE"):
            os.environ.pop(k, None)

    # ---- workspace builder -------------------------------------------------
    def _ws(self, manifest_rows, sidecars=None):
        ws = Path(tempfile.mkdtemp()).resolve()
        au = ws / ".auditooor"
        (au / "hunt_findings_sidecars").mkdir(parents=True)
        with (au / "inscope_units.jsonl").open("w") as fh:
            for r in manifest_rows:
                fh.write(json.dumps(r) + "\n")
        # materialize each cited source file so it exists on disk.
        for r in manifest_rows:
            fp = ws / r["file"]
            fp.parent.mkdir(parents=True, exist_ok=True)
            if not fp.exists():
                fp.write_text(r.get("_src", "// stub\n"), encoding="utf-8")
        for name, obj in (sidecars or {}).items():
            (au / "hunt_findings_sidecars" / name).write_text(
                json.dumps(obj), encoding="utf-8")
        return ws

    # ---- language-registration invariants ---------------------------------
    def test_manifest_seed_langs(self):
        self.assertIn("oscript", self.vmf._MANIFEST_SEED_LANGS)
        # engine + walked langs must NEVER be manifest-seeded (byte-identity guard).
        for walked in ("solidity", "go", "rust", "vyper", "move", "cairo", "noir"):
            self.assertNotIn(walked, self.vmf._MANIFEST_SEED_LANGS)

    # ---- value-moving-functions: manifest seeding -------------------------
    def _mixed_rows(self):
        return [
            # oscript file A: payment value-mover -> transfer_hit
            {"file": "src/aa/a.oscript", "function": "case_0", "lang": "oscript",
             "value_movers": ["payment"], "state_writes": []},
            # oscript file B: only a state write -> ledger_write_hit
            {"file": "src/aa/b.oscript", "function": "messages", "lang": "oscript",
             "value_movers": ["state"], "state_writes": ["'balance_'||trigger.address"]},
            # oscript getter: no value_movers/state_writes -> NOT value-moving
            {"file": "src/aa/a.oscript", "function": "$getter", "lang": "oscript",
             "value_movers": [], "state_writes": []},
            # a real Solidity value-mover, from a source walk (NOT manifest-seeded)
            {"file": "src/Sol.sol", "function": "withdraw", "lang": "solidity",
             "_src": "contract C {\n function withdraw() external {\n"
                     "   token.transfer(msg.sender, amount);\n }\n}\n"},
        ]

    def test_seed_records(self):
        ws = self._ws(self._mixed_rows())
        recs = self.vmf._manifest_declarative_value_moving_records(ws)
        by = {(r["file"], r["function"]): r for r in recs}
        # file A payment -> transfer_hit
        self.assertIn(("src/aa/a.oscript", "case_0"), by)
        self.assertTrue(by[("src/aa/a.oscript", "case_0")]["transfer_hit"])
        # file B state write -> ledger_write_hit (transfer_hit False)
        self.assertIn(("src/aa/b.oscript", "messages"), by)
        self.assertTrue(by[("src/aa/b.oscript", "messages")]["ledger_write_hit"])
        self.assertFalse(by[("src/aa/b.oscript", "messages")]["transfer_hit"])
        # the getter is NOT value-moving
        self.assertNotIn(("src/aa/a.oscript", "$getter"), by)
        # a solidity row is NEVER manifest-seeded (it comes from the source walk)
        self.assertFalse(any(r["language"] == "solidity" for r in recs))
        self.assertNotIn(("src/Sol.sol", "withdraw"), by)

    def test_full_enumerate_has_both_langs(self):
        ws = self._ws(self._mixed_rows())
        recs = self.vmf.enumerate_value_moving(ws)
        langs = {r["language"] for r in recs}
        self.assertIn("oscript", langs)   # manifest-seeded
        self.assertIn("sol", langs)       # source-walked (byte-identical path)
        # exactly the two value-moving oscript units, no getter
        osc = sorted(r["function"] for r in recs if r["language"] == "oscript")
        self.assertEqual(osc, ["case_0", "messages"])

    def test_value_moving_killswitch(self):
        ws = self._ws(self._mixed_rows())
        os.environ["AUDITOOOR_OSCRIPT_VALUE_MOVING"] = "0"
        recs = self.vmf.enumerate_value_moving(ws)
        self.assertFalse(any(r["language"] == "oscript" for r in recs))
        # the solidity source-walk record is unaffected by the oscript kill-switch
        self.assertTrue(any(r["language"] == "sol" for r in recs))

    # ---- invariant-fuzz: hunt-sidecar credit ------------------------------
    def _anchor_sidecar(self, file, applies="no"):
        return {"function_anchor": {"file": file, "function": "case_0", "line": 1},
                "task_type": "hunt",
                "verification_tier": "tier-1-source-read-verified",
                "result": {"applies_to_target": applies,
                           "file_line": f"{file}:1-9"}}

    def test_hunt_credit_and_no_overcredit(self):
        rows = self._mixed_rows()
        # sidecar anchors ONLY to file A (an oscript file) + one anchoring a .sol
        sidecars = {
            "a.json": self._anchor_sidecar("src/aa/a.oscript", "no"),
            "sol.json": self._anchor_sidecar("src/Sol.sol", "yes"),  # engine lang
        }
        ws = self._ws(rows, sidecars)
        cred = self.ifc._llm_hunt_only_covered_files(ws)
        # file A credited; file B (no sidecar) NOT credited
        self.assertIn("src/aa/a.oscript", cred)
        self.assertNotIn("src/aa/b.oscript", cred)
        # the .sol file is an ENGINE language -> NEVER credited via this path
        self.assertNotIn("src/Sol.sol", cred)
        self.assertFalse(any(str(f).endswith((".sol", ".go", ".rs", ".vy")) for f in cred))

    def test_hunt_credit_killswitch(self):
        rows = self._mixed_rows()
        ws = self._ws(rows, {"a.json": self._anchor_sidecar("src/aa/a.oscript", "no")})
        os.environ["AUDITOOOR_OSCRIPT_HUNT_COVERAGE"] = "0"
        self.assertEqual(self.ifc._llm_hunt_only_covered_files(ws), set())

    def test_stub_sidecar_not_credited(self):
        # a sidecar with NO applies_to_target disposition is not a hunt verdict
        stub = {"function_anchor": {"file": "src/aa/a.oscript", "function": "x"},
                "task_type": "hunt", "result": {}}
        ws = self._ws(self._mixed_rows(), {"stub.json": stub})
        self.assertNotIn("src/aa/a.oscript", self.ifc._llm_hunt_only_covered_files(ws))

    def test_asset_coverage_end_to_end(self):
        rows = self._mixed_rows()
        sidecars = {"a.json": self._anchor_sidecar("src/aa/a.oscript", "no")}
        ws = self._ws(rows, sidecars)
        # produce the canonical value_moving_functions.json the gate reads
        self.vmf.run(ws)
        ac = self.ifc._asset_coverage(ws, [])
        self.assertTrue(ac["applicable"])
        osc = lambda L: {f for f in L if f.endswith((".oscript", ".aa"))}
        vm = osc(ac["value_moving"])
        self.assertEqual(vm, {"src/aa/a.oscript", "src/aa/b.oscript"})
        # A (hunted) covered; B (not hunted) a gap; no overlap
        self.assertIn("src/aa/a.oscript", ac["covered"])
        self.assertIn("src/aa/b.oscript", ac["gaps"])
        self.assertEqual(osc(ac["covered"]) & osc(ac["gaps"]), set())


if __name__ == "__main__":
    unittest.main()
