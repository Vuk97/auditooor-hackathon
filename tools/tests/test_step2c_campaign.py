#!/usr/bin/env python3
# <!-- r36-rebuttal: lane STEP2C-CAMPAIGN-CANONICAL registered in commit message -->
"""step2c-campaign canonical helper - pins the 5 hard-won lessons (strata 2026-06-30)."""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent / "step2c-campaign.py"
_spec = importlib.util.spec_from_file_location("s2c", _T)
s2c = importlib.util.module_from_spec(_spec)
sys.modules["s2c"] = s2c
_spec.loader.exec_module(s2c)


class _NS:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class EmitConfigTest(unittest.TestCase):
    def test_target_is_absolute_not_dot(self):
        ws = Path(tempfile.mkdtemp(prefix="s2c_"))
        hdir = ws / "chimera_harnesses" / "Foo"
        hdir.mkdir(parents=True)
        rc = s2c.cmd_emit_config(_NS(
            workspace=str(ws), harness_dir=str(hdir), contract="Foo",
            test_limit=1_200_000, seq_len=50, workers=8))
        self.assertEqual(rc, 0)
        cfg = json.loads((hdir / "medusa.campaign.json").read_text())
        tgt = cfg["compilation"]["platformConfig"]["target"]
        self.assertTrue(Path(tgt).is_absolute(), f"target must be absolute (L1), got {tgt}")
        self.assertNotEqual(tgt, ".")
        self.assertEqual(cfg["fuzzing"]["testLimit"], 1_200_000)
        self.assertEqual(cfg["fuzzing"]["callSequenceLength"], 50)


class FinalizeTest(unittest.TestCase):
    def _ws(self):
        ws = Path(tempfile.mkdtemp(prefix="s2c_"))
        (ws / ".auditooor" / "mvc_sidecar").mkdir(parents=True)
        (ws / ".auditooor" / "fuzz_logs").mkdir(parents=True)
        return ws

    def _mvc(self, ws, name):
        (ws / ".auditooor" / "mvc_sidecar" / f"mvc-{name}.json").write_text(
            json.dumps({"verdict": "non-vacuous", "mutants_killed": 1}), encoding="utf-8")

    def test_total_calls_emitted_and_clean(self):
        ws = self._ws()
        self._mvc(ws, "Good")
        log = ws / ".auditooor" / "fuzz_logs" / "medusa_Good.log"
        log.write_text("elapsed: 100s, calls: 1205980 (9000/s)\n"
                       "[PASSED] Good.echidna_conservation()\n"
                       "[PASSED] Good.echidna_reachability()\nTest summary: ok\n",
                       encoding="utf-8")
        rc = s2c.cmd_finalize(_NS(
            workspace=str(ws), harness="Good", contract="Good", log=str(log),
            harness_rel="", mvc_sidecar="", min_calls=1_000_000))
        self.assertEqual(rc, 0)  # clean
        self.assertIn("Total calls: 1205980", log.read_text())  # L3
        r = json.loads((ws / ".auditooor" / "fuzz_campaign_receipt.json").read_text())
        self.assertEqual(r["schema"], s2c.SCHEMA)
        row = r["campaigns"][0]
        self.assertTrue(row["clean"])
        self.assertEqual(row["result"]["calls"], 1205980)
        self.assertEqual(row["result"]["failed"], 0)
        self.assertGreaterEqual(row["non_vacuity_kills"], 1)
        per = json.loads((ws / "chimera_harnesses" / "Good" / "campaign_result.json").read_text())
        self.assertEqual(per["schema"], "auditooor.medusa_campaign_result.v1")
        self.assertEqual(per["campaign_calls"], 1205980)
        self.assertEqual(per["seq_len"], 50)
        self.assertEqual(per["campaign_status"], "pass")

    def test_shallow_campaign_is_recorded_but_not_credited(self):
        ws = self._ws()
        self._mvc(ws, "Shallow")
        log = ws / ".auditooor" / "fuzz_logs" / "medusa_Shallow.log"
        log.write_text("calls: 1200000\n[PASSED] Shallow.echidna_x()\n", encoding="utf-8")
        rc = s2c.cmd_finalize(_NS(
            workspace=str(ws), harness="Shallow", contract="Shallow", log=str(log),
            harness_rel="", mvc_sidecar="", min_calls=1_000_000, seq_len=49))
        self.assertEqual(rc, 1)
        per = json.loads((ws / "chimera_harnesses" / "Shallow" / "campaign_result.json").read_text())
        self.assertEqual(per["campaign_calls"], 1200000)
        self.assertEqual(per["campaign_status"], "failed")

    def test_forge_std_artifact_excluded_from_failed(self):
        # L2: a stdError forge-std panic must NOT count as a CUT failure.
        ws = self._ws()
        self._mvc(ws, "Tdc")
        log = ws / ".auditooor" / "fuzz_logs" / "medusa_Tdc.log"
        log.write_text(
            "calls: 1203538 (3500/s)\n"
            "[PASSED] Tdc.echidna_depositor_holds_zero_asset()\n"
            "[FAILED] Tdc.echidna_reachability()\n"
            "  call: stdError.indexOOBError() reverted with panic\n"
            "Test summary: 1 failed\n", encoding="utf-8")
        rc = s2c.cmd_finalize(_NS(
            workspace=str(ws), harness="Tdc", contract="Tdc", log=str(log),
            harness_rel="", mvc_sidecar="", min_calls=1_000_000))
        self.assertEqual(rc, 0, "forge-std-only failure must classify clean")
        row = json.loads((ws / ".auditooor" / "fuzz_campaign_receipt.json").read_text())["campaigns"][0]
        self.assertEqual(row["result"]["failed"], 0)  # artifact excluded
        self.assertIn("Tdc.echidna_reachability()", row["result"]["forge_std_artifacts"])
        self.assertTrue(row["clean"])

    def test_real_cut_failure_stays_failed(self):
        # a genuine assertion break (not forge-std) must remain a real failure.
        ws = self._ws()
        self._mvc(ws, "Bad")
        log = ws / ".auditooor" / "fuzz_logs" / "medusa_Bad.log"
        log.write_text(
            "calls: 1100000 (9000/s)\n"
            "[FAILED] Bad.echidna_nav_conservation()\n"
            "  assertion failed: nav != jrt+srt+reserve\n"
            "Test summary: 1 failed\n", encoding="utf-8")
        rc = s2c.cmd_finalize(_NS(
            workspace=str(ws), harness="Bad", contract="Bad", log=str(log),
            harness_rel="", mvc_sidecar="", min_calls=1_000_000))
        self.assertEqual(rc, 1, "real CUT break must be NOT-clean")
        row = json.loads((ws / ".auditooor" / "fuzz_campaign_receipt.json").read_text())["campaigns"][0]
        self.assertEqual(row["result"]["failed"], 1)
        self.assertFalse(row["clean"])

    def test_below_min_calls_not_clean(self):
        ws = self._ws()
        self._mvc(ws, "Short")
        log = ws / ".auditooor" / "fuzz_logs" / "medusa_Short.log"
        log.write_text("calls: 50000 (9000/s)\n[PASSED] Short.echidna_x()\nTest summary: ok\n",
                       encoding="utf-8")
        rc = s2c.cmd_finalize(_NS(
            workspace=str(ws), harness="Short", contract="Short", log=str(log),
            harness_rel="", mvc_sidecar="", min_calls=1_000_000))
        self.assertEqual(rc, 1)  # 50k < 1M
        row = json.loads((ws / ".auditooor" / "fuzz_campaign_receipt.json").read_text())["campaigns"][0]
        self.assertFalse(row["clean"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
