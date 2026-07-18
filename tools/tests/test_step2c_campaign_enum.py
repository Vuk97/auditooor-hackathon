#!/usr/bin/env python3
# <!-- r36-rebuttal: lane STEP2C-CAMPAIGN-CANONICAL registered in commit message -->
"""E3 - step2c-campaign receipt enumeration-completeness + echidna-falsification.

Guards the two structural cherry-pick gaps in tools/step2c-campaign.py:
  (a) ENUMERATION: a campaign present in the run index `_campaign_index.log` but ABSENT
      from fuzz_campaign_receipt.json is flagged `fuzz-campaign-omitted`.
  (b) FALSIFICATION: an echidna `falsified!` / `failed!` line (which the medusa-only
      `[FAILED]` regex MISSES) is detected as a failure, and a falsified campaign with
      no terminal adjudication artifact is flagged `fuzz-falsification-unadjudicated`.

DOCTRINE the tests pin:
  - default mode remains warning-compatible. STRICT env => every missing or
    inconsistent campaign record fails closed.
  - NEVER-FALSE-PASS: a receipt that enumerates ALL logged campaigns and adjudicates
    every falsification still passes (advisory AND strict).
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent / "step2c-campaign.py"
_spec = importlib.util.spec_from_file_location("s2c_enum", _T)
s2c = importlib.util.module_from_spec(_spec)
sys.modules["s2c_enum"] = s2c
_spec.loader.exec_module(s2c)

_STRICT = s2c._STRICT_ENV  # "AUDITOOOR_FUZZ_CAMPAIGN_ENUM_STRICT"


class _NS:
    def __init__(self, **kw):
        self.__dict__.update(kw)


# --- a minimal real-shaped run index (2 campaigns) ---------------------------------
_INDEX_TWO = (
    "=== [17:46:09] campaign solvency (contract=SSVClusterSolvencyMedusa limit=500000) ===\n"
    "    -> rc=0; tail:\n"
    "echidna_cluster_solvency_no_over_withdraw: passing\n"
    "Total calls: 500172\n"
    "=== [17:50:17] campaign clusters-lifecycle (contract=SSVClustersEchidna limit=500000) ===\n"
    "    -> rc=1; tail:\n"
    "echidna_fee_index_current_after_settle: passing\n"
    "echidna_eth_balance_accounting: failed!\xf0\x9f\x92\xa5  \n"
    "Total calls: 500279\n"
    "=== [18:08:17] ALL CAMPAIGNS DONE ===\n"
)


def _clean_env():
    os.environ.pop(_STRICT, None)


class _Base(unittest.TestCase):
    def setUp(self):
        self._saved = os.environ.get(_STRICT)
        _clean_env()

    def tearDown(self):
        if self._saved is None:
            os.environ.pop(_STRICT, None)
        else:
            os.environ[_STRICT] = self._saved

    def _ws(self):
        ws = Path(tempfile.mkdtemp(prefix="s2c_enum_"))
        (ws / ".auditooor" / "fuzz_logs").mkdir(parents=True)
        return ws

    def _write_index(self, ws, text=_INDEX_TWO):
        p = ws / ".auditooor" / "fuzz_logs" / "_campaign_index.log"
        p.write_text(text, encoding="utf-8")
        return p

    def _write_receipt(self, ws, names):
        p = ws / ".auditooor" / "fuzz_campaign_receipt.json"
        p.write_text(json.dumps({
            "schema": s2c.SCHEMA, "workspace": ws.name,
            "campaigns": [{"engine": "echidna", "name": n, "contract": None} for n in names],
        }), encoding="utf-8")
        return p


# =========================================================================
#  Pure-parse layer
# =========================================================================
class FalsificationDetectionTest(_Base):
    def test_echidna_failed_bang_detected(self):
        # E3 (b): the exact SSV line the medusa-only _FAIL_RE misses.
        hits = s2c._log_has_falsification("echidna_eth_balance_accounting: failed!\U0001f4a5\n")
        self.assertTrue(hits, "echidna `failed!` must be detected as a falsification")
        self.assertIn("echidna_eth_balance_accounting", hits[0])

    def test_echidna_falsified_detected(self):
        hits = s2c._log_has_falsification("prop_conservation(): falsified!\n")
        self.assertTrue(hits)
        self.assertIn("prop_conservation", hits[0])

    def test_medusa_failed_still_detected(self):
        # backward-compat: medusa `[FAILED]` still recognized.
        hits = s2c._log_has_falsification("[FAILED] Harness.echidna_nav_conservation()\n")
        self.assertEqual(len(hits), 1)
        self.assertIn("echidna_nav_conservation", hits[0])

    def test_passing_never_matches(self):
        txt = ("echidna_a: passing\n[PASSED] H.echidna_b()\n"
               "echidna_c: passing\nUnique instructions: 9995\nTotal calls: 500172\n")
        self.assertEqual(s2c._log_has_falsification(txt), [],
                         "no passing/[PASSED] line may be read as a falsification")


class ParseIndexTest(_Base):
    def test_parse_two_campaigns_plus_summary_ignored(self):
        rows = s2c.parse_campaign_index(_INDEX_TWO)
        names = [r["name"] for r in rows]
        self.assertEqual(names, ["solvency", "clusters-lifecycle"])  # "ALL ... DONE" dropped
        self.assertFalse(rows[0]["falsified"])
        self.assertTrue(rows[1]["falsified"])          # rc=1 AND `failed!`
        self.assertTrue(rows[1]["falsified_props"])

    def test_rc_nonzero_alone_is_falsified(self):
        idx = ("=== [00:00:00] campaign x (contract=Xh limit=1) ===\n"
               "    -> rc=1; tail:\nsome unrelated tail\n")
        rows = s2c.parse_campaign_index(idx)
        self.assertTrue(rows[0]["falsified"])


# =========================================================================
#  Enumeration completeness (E3 a)
# =========================================================================
class EnumerationTest(_Base):
    def test_omitted_campaign_flagged_under_strict(self):
        ws = self._ws()
        self._write_index(ws)
        # receipt has ONLY solvency -> clusters-lifecycle is cherry-picked out.
        self._write_receipt(ws, ["SSVClusterSolvency"])
        rep = s2c.enumerate_and_adjudicate(
            ws, _INDEX_TWO, s2c._load_receipt(ws))
        self.assertIn("fuzz-campaign-omitted", rep["flags"])
        self.assertEqual([r["name"] for r in rep["omitted"]], ["clusters-lifecycle"])

    def test_all_enumerated_passes(self):
        ws = self._ws()
        self._write_index(ws)
        # both present (receipt names normalize-match both index contracts) AND the
        # falsification is adjudicated -> no flags at all (never-false-pass positive).
        self._write_receipt(ws, ["SSVClusterSolvency", "SSVClusters"])
        (ws / ".auditooor" / "dispositions.json").write_text(
            json.dumps({"adjudicated": ["clusters-lifecycle"]}), encoding="utf-8")
        rep = s2c.enumerate_and_adjudicate(ws, _INDEX_TWO, s2c._load_receipt(ws))
        self.assertEqual(rep["omitted"], [])
        self.assertEqual(rep["flags"], [], f"all-enumerated+adjudicated must pass, got {rep['flags']}")

    def test_friendly_name_matches_receipt_contract_name(self):
        # index friendly `solvency` / contract `SSVClusterSolvencyMedusa` must match
        # receipt name `SSVClusterSolvency` (suffix-strip + substring join).
        row = {"name": "solvency", "contract": "SSVClusterSolvencyMedusa"}
        self.assertTrue(s2c._campaign_in_receipt(row, {"ssvclustersolvency"}))
        # but an unrelated receipt name must NOT accidentally match.
        row2 = {"name": "clusters-lifecycle", "contract": "SSVClustersEchidna"}
        self.assertFalse(s2c._campaign_in_receipt(row2, {"ssvclustersolvency"}))


# =========================================================================
#  Falsification adjudication (E3 b)
# =========================================================================
class AdjudicationTest(_Base):
    def test_falsified_without_disposition_flagged(self):
        ws = self._ws()
        self._write_index(ws)
        self._write_receipt(ws, ["SSVClusterSolvency", "SSVClusters"])  # enumerated ...
        # ... but NO adjudication artifact for the falsified clusters-lifecycle.
        rep = s2c.enumerate_and_adjudicate(ws, _INDEX_TWO, s2c._load_receipt(ws))
        self.assertIn("fuzz-falsification-unadjudicated", rep["flags"])
        self.assertEqual([r["name"] for r in rep["unadjudicated"]], ["clusters-lifecycle"])

    def test_falsified_with_disposition_cleared(self):
        ws = self._ws()
        self._write_index(ws)
        self._write_receipt(ws, ["SSVClusterSolvency", "SSVClusters"])
        (ws / ".auditooor" / "fuzz_falsification_dispositions.json").write_text(
            json.dumps([{"campaign": "clusters-lifecycle", "verdict": "known-issue-refuted"}]),
            encoding="utf-8")
        rep = s2c.enumerate_and_adjudicate(ws, _INDEX_TWO, s2c._load_receipt(ws))
        self.assertEqual(rep["unadjudicated"], [])
        self.assertNotIn("fuzz-falsification-unadjudicated", rep["flags"])


# =========================================================================
#  verify CLI - advisory-first / strict rc semantics
# =========================================================================
class VerifyCliTest(_Base):
    def _run(self, ws):
        return s2c.cmd_verify(_NS(workspace=str(ws), index=""))

    def test_advisory_default_rc0_even_with_flags(self):
        ws = self._ws()
        self._write_index(ws)
        self._write_receipt(ws, ["SSVClusterSolvency"])  # omits clusters-lifecycle
        _clean_env()
        self.assertEqual(self._run(ws), 0, "advisory (env unset) must be rc=0 despite flags")

    def test_strict_env_rc1_on_flags(self):
        ws = self._ws()
        self._write_index(ws)
        self._write_receipt(ws, ["SSVClusterSolvency"])
        os.environ[_STRICT] = "1"
        self.assertEqual(self._run(ws), 1, "strict env must FAIL on omitted/unadjudicated")

    def test_strict_env_rc0_when_clean(self):
        # NEVER-FALSE-PASS: full enumeration + adjudication -> rc=0 even under strict.
        ws = self._ws()
        self._write_index(ws)
        self._write_receipt(ws, ["SSVClusterSolvency", "SSVClusters"])
        (ws / ".auditooor" / "dispositions.json").write_text(
            json.dumps({"clusters-lifecycle": "refuted"}), encoding="utf-8")
        os.environ[_STRICT] = "1"
        self.assertEqual(self._run(ws), 0, "clean receipt must pass even under strict")

    def test_missing_index_is_warning_default_but_strict_failure(self):
        ws = self._ws()  # no index written
        self._write_receipt(ws, ["Whatever"])
        os.environ[_STRICT] = "1"
        self.assertEqual(self._run(ws), 1, "strict requires an execution index")


# =========================================================================
#  finalize integration - env-unset byte-parity + strict cross-check
# =========================================================================
class FinalizeCrossCheckTest(_Base):
    def _mvc(self, ws, name):
        d = ws / ".auditooor" / "mvc_sidecar"
        d.mkdir(parents=True, exist_ok=True)
        (d / f"mvc-{name}.json").write_text(
            json.dumps({"verdict": "non-vacuous", "mutants_killed": 1}), encoding="utf-8")

    def test_medusa_only_log_unaffected_env_unset(self):
        # never-retro-red: a plain medusa log with no index present behaves as before.
        ws = self._ws()
        self._mvc(ws, "Good")
        log = ws / ".auditooor" / "fuzz_logs" / "medusa_Good.log"
        log.write_text("calls: 1205980 (9000/s)\n[PASSED] Good.echidna_conservation()\n"
                       "[PASSED] Good.echidna_reachability()\nTest summary: ok\n",
                       encoding="utf-8")
        _clean_env()
        rc = s2c.cmd_finalize(_NS(workspace=str(ws), harness="Good", contract="Good",
                                  log=str(log), harness_rel="", mvc_sidecar="",
                                  min_calls=1_000_000))
        self.assertEqual(rc, 0, "clean medusa campaign still rc=0 (byte-parity, no index)")

    def test_echidna_falsified_log_not_clean(self):
        # E3 (b) at the finalize layer: an echidna `failed!` line makes the row NOT clean.
        ws = self._ws()
        self._mvc(ws, "Clu")
        log = ws / ".auditooor" / "fuzz_logs" / "echidna_Clu.log"
        log.write_text("calls: 1100000 (9000/s)\n"
                       "echidna_fee_index_current_after_settle: passing\n"
                       "echidna_eth_balance_accounting: failed!\n"
                       "Total calls: 1100000\n", encoding="utf-8")
        _clean_env()
        rc = s2c.cmd_finalize(_NS(workspace=str(ws), harness="Clu", contract="Clu",
                                  log=str(log), harness_rel="", mvc_sidecar="",
                                  min_calls=1_000_000))
        self.assertEqual(rc, 1, "an echidna falsification must make the campaign NOT-clean")
        row = json.loads((ws / ".auditooor" / "fuzz_campaign_receipt.json").read_text())["campaigns"][0]
        self.assertEqual(row["result"]["failed"], 1)
        self.assertFalse(row["clean"])

    def test_finalize_strict_flags_omitted_sibling(self):
        # With an index that logs a SECOND campaign never finalized, strict finalize
        # of the first campaign flags the omission; advisory finalize does not flip rc.
        ws = self._ws()
        self._mvc(ws, "SSVClusterSolvency")
        self._write_index(ws)  # logs solvency + clusters-lifecycle
        log = ws / ".auditooor" / "fuzz_logs" / "echidna_solvency.log"
        log.write_text("calls: 1205980 (9000/s)\n"
                       "echidna_cluster_solvency_no_over_withdraw: passing\n"
                       "Total calls: 1205980\n", encoding="utf-8")
        # advisory: clean campaign stays rc=0 even though clusters-lifecycle is omitted.
        _clean_env()
        rc_adv = s2c.cmd_finalize(_NS(workspace=str(ws), harness="SSVClusterSolvency",
                                      contract="SSVClusterSolvency", log=str(log),
                                      harness_rel="", mvc_sidecar="", min_calls=1_000_000))
        self.assertEqual(rc_adv, 0, "advisory finalize must not retro-red on omission")
        # strict: same state now fails on the omitted + unadjudicated flags.
        os.environ[_STRICT] = "1"
        rc_strict = s2c.cmd_finalize(_NS(workspace=str(ws), harness="SSVClusterSolvency",
                                         contract="SSVClusterSolvency", log=str(log),
                                         harness_rel="", mvc_sidecar="", min_calls=1_000_000))
        self.assertEqual(rc_strict, 1, "strict finalize FAILS while a logged sibling is omitted")


if __name__ == "__main__":
    unittest.main(verbosity=2)
