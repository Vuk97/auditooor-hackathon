#!/usr/bin/env python3
# <!-- r36-rebuttal: lane FIX-HONEST-ZERO-VERIFY registered via agent-pathspec-register.py; orchestrator commits; sibling files untouched -->
"""test_f4_recall_floor.py

synthetic_fixture: true

Guards F4-floor (spec section F4, items E4.1 + E4.2 - the recall floor).

E4.1 - tools/auditor-backtest.py gains a HUNT-path mode (--mode hunt) that grades
       the LLM hunt path (not the detector layer) against a held-out known-bug
       corpus and reports HUNT-RECALL. Languages with no detector arm record
       engine='llm-hunt-only'. The hunt callable is injectable so the path is
       gradeable offline with a deterministic stub.

E4.2 - tools/honest-zero-verify.py gains a recall-floor check in the recompute:
       genuine-0 requires held-out hunt-recall >= floor (default 0.5) OR a
       waiver, computed PER LANGUAGE SUB-TREE. A mixed repo where solidity=100%
       but circom=0 FAILS (the Solidity recall must not mask the zk zero).

The recall is RECOMPUTED from the per-case hunt records, never read from a
written verdict file.
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
AB_PATH = REPO_ROOT / "tools" / "auditor-backtest.py"
HZV_PATH = REPO_ROOT / "tools" / "honest-zero-verify.py"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


AB = _load("auditor_backtest_f4floor", AB_PATH)
HZV = _load("hzv_f4floor", HZV_PATH)


# --------------------------------------------------------------------------
# E4.1: HUNT-path mode in auditor-backtest.py
# --------------------------------------------------------------------------
class TestHuntModeE41(unittest.TestCase):
    def _local_case(self, d, rel, vuln_class, line, body="contract C {}\n"):
        base = Path(d)
        fp = base / rel
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(body)
        return {"id": "H", "repo": "o/r", "prefix_ref": "abc",
                "vuln_class": vuln_class, "file_line": f"{rel}:{line}"}

    def test_hunt_rediscovered_at_line_is_caught(self):
        with tempfile.TemporaryDirectory() as d:
            case = self._local_case(d, "src/Vault.sol", "reentrancy", 140)
            stub = lambda c, sp, vc: {"ran": True, "rediscovered": True,
                                      "fired_at_line": 145, "confidence": 0.9,
                                      "reason": "stub"}
            rec = AB.hunt_case(case, d, d, hunt_fn=stub)
            self.assertEqual(rec["outcome"], "CAUGHT")
            self.assertTrue(rec["rediscovered"])
            self.assertEqual(rec["engine"], "llm-hunt")  # solidity has a detector arm

    def test_hunt_silent_is_missed(self):
        with tempfile.TemporaryDirectory() as d:
            case = self._local_case(d, "src/Vault.sol", "reentrancy", 140)
            stub = lambda c, sp, vc: {"ran": True, "rediscovered": False,
                                      "reason": "stub-silent"}
            rec = AB.hunt_case(case, d, d, hunt_fn=stub)
            self.assertEqual(rec["outcome"], "MISSED")
            self.assertFalse(rec["rediscovered"])
            self.assertIn("did-not-rediscover", rec["missing_capability"])

    def test_hunt_not_run_is_na_not_missed(self):
        with tempfile.TemporaryDirectory() as d:
            case = self._local_case(d, "src/Vault.sol", "reentrancy", 140)
            stub = lambda c, sp, vc: {"ran": False, "reason": "no-consent"}
            rec = AB.hunt_case(case, d, d, hunt_fn=stub)
            # hunt never ran -> NA, never a silent miss.
            self.assertEqual(rec["outcome"], "NA")
            self.assertEqual(rec["missing_capability"], "hunt-not-run")

    def test_hunt_partial_when_off_cited_line(self):
        with tempfile.TemporaryDirectory() as d:
            case = self._local_case(d, "src/Vault.sol", "reentrancy", 140)
            stub = lambda c, sp, vc: {"ran": True, "rediscovered": True,
                                      "fired_at_line": 400}  # > 25 away
            rec = AB.hunt_case(case, d, d, hunt_fn=stub)
            self.assertEqual(rec["outcome"], "PARTIAL")

    def test_llm_hunt_only_engine_for_languages_without_detector_arm(self):
        with tempfile.TemporaryDirectory() as d:
            # circom has no static detector arm -> engine='llm-hunt-only'.
            case = self._local_case(d, "circuits/main.circom", "under-constraint",
                                    10, body="template Main() {}\n")
            stub = lambda c, sp, vc: {"ran": True, "rediscovered": True,
                                      "fired_at_line": 10}
            rec = AB.hunt_case(case, d, d, hunt_fn=stub)
            self.assertEqual(rec["engine"], "llm-hunt-only")
            self.assertEqual(rec["outcome"], "CAUGHT")

    def test_hunt_non_fetchable_is_na(self):
        with tempfile.TemporaryDirectory() as d:
            case = {"id": "NF", "vuln_class": "oracle",
                    "file_line": "src/X.sol:1", "fetch_status": "dead_source"}
            stub = lambda c, sp, vc: {"ran": True, "rediscovered": True}
            rec = AB.hunt_case(case, None, d, hunt_fn=stub)
            self.assertEqual(rec["outcome"], "NA")
            self.assertEqual(rec["missing_capability"], "non-fetchable")

    def test_hunt_recall_excludes_na_from_denominator(self):
        recs = [
            {"outcome": "CAUGHT"}, {"outcome": "CAUGHT"},
            {"outcome": "MISSED"}, {"outcome": "NA"}, {"outcome": "NA"},
        ]
        r = AB.hunt_recall(recs)
        # 2 caught / 3 scorable (NA excluded) = 66.7%
        self.assertEqual(r["scorable"], 3)
        self.assertAlmostEqual(r["recall"], 2 / 3, places=4)
        self.assertEqual(r["na"], 2)

    def test_cli_hunt_mode_emits_recall_json_offline_na(self):
        """The CLI --mode hunt runs end-to-end offline. With no consent the
        default hunt callable does not run -> all NA, but the envelope carries a
        hunt_recall block and exits 0 (measurement tool)."""
        with tempfile.TemporaryDirectory() as d:
            cases = Path(d) / "cases.jsonl"
            cases.write_text(json.dumps(
                {"id": "C1", "vuln_class": "reentrancy",
                 "file_line": "src/V.sol:1", "fetch_status": "dead_source"}) + "\n")
            env = dict(os.environ)
            env.pop("AUDITOOOR_LLM_NETWORK_CONSENT", None)
            proc = subprocess.run(
                [sys.executable, str(AB_PATH), "--mode", "hunt",
                 "--cases", str(cases), "--json"],
                capture_output=True, text=True, timeout=120, env=env)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["mode"], "hunt")
            self.assertIn("hunt_recall", payload)
            self.assertEqual(payload["schema"], AB.HUNT_SCHEMA)


# --------------------------------------------------------------------------
# E4.2: recall-floor check in honest-zero-verify.py
# --------------------------------------------------------------------------
def _write_hunt_records(ws: Path, records: list) -> None:
    a = ws / ".auditooor"
    a.mkdir(parents=True, exist_ok=True)
    (a / "hunt_recall_backtest.jsonl").write_text(
        "\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")


def _records(lang: str, caught: int, total: int) -> list:
    """total CAUGHT/MISSED hunt-case records for one language."""
    out = []
    for i in range(total):
        out.append({"language": lang,
                    "outcome": "CAUGHT" if i < caught else "MISSED",
                    "id": f"{lang}-{i}", "vuln_class": "x"})
    return out


class TestRecallFloorE42(unittest.TestCase):
    def test_two_of_ten_refused(self):
        """A ws recalling 2/10 (below 0.5 floor) is refused genuine-0."""
        ws = Path(tempfile.mkdtemp())
        _write_hunt_records(ws, _records("solidity", 2, 10))
        ok, detail, _fp = HZV._check_recall_floor(ws)
        self.assertFalse(ok, detail)
        self.assertIn("below floor", detail)
        self.assertIn("solidity", detail)

    def test_seven_of_ten_allowed(self):
        """7/10 (>= 0.5) clears the floor."""
        ws = Path(tempfile.mkdtemp())
        _write_hunt_records(ws, _records("solidity", 7, 10))
        ok, detail, fp = HZV._check_recall_floor(ws)
        self.assertTrue(ok, detail)
        self.assertIn("cleared", detail)
        self.assertTrue(fp.startswith("recall:"))

    def test_waiver_marker_allows_low_recall(self):
        """An l37-rebuttal 'recall_floor' line flips 2/10 to ok-rebuttal."""
        ws = Path(tempfile.mkdtemp())
        _write_hunt_records(ws, _records("solidity", 2, 10))
        (ws / ".auditooor" / "l37-rebuttal").write_text(
            "other\nrecall_floor\n", encoding="utf-8")
        ok, detail, fp = HZV._check_recall_floor(ws)
        self.assertTrue(ok, detail)
        self.assertIn("ok-rebuttal", detail)
        self.assertEqual(fp, "recall:rebuttal")

    def test_mixed_repo_solidity_100_circom_0_fails(self):
        """PER-LANGUAGE SUB-TREE: solidity=100% must NOT mask circom=0%."""
        ws = Path(tempfile.mkdtemp())
        recs = _records("solidity", 10, 10) + _records("circom", 0, 10)
        _write_hunt_records(ws, recs)
        ok, detail, _fp = HZV._check_recall_floor(ws)
        self.assertFalse(ok, "circom=0 must fail even though solidity=100%")
        # circom appears in the FAILURES segment (before any "[ok:" cleared list).
        fail_segment = detail.split("[ok:")[0]
        self.assertIn("circom", fail_segment)
        # solidity is NOT in the failures segment (it cleared the floor).
        self.assertNotIn("solidity=", fail_segment)

    def test_present_language_no_corpus_is_waived_not_zeroed(self):
        """A present source language with NO held-out corpus emits a typed
        <lang>-recall-corpus-absent waiver (logged) and PASSES - never a silent
        zero, never an un-waivable brick."""
        ws = Path(tempfile.mkdtemp())
        a = ws / ".auditooor"
        a.mkdir(parents=True, exist_ok=True)
        # present solidity source, but no hunt_recall_backtest.jsonl.
        (ws / "src").mkdir(parents=True, exist_ok=True)
        (ws / "src" / "Vault.sol").write_text("contract Vault {}\n")
        ok, detail, _fp = HZV._check_recall_floor(ws)
        self.assertTrue(ok, detail)
        self.assertIn("solidity-recall-corpus-absent", detail)
        # the waiver was LOGGED (auditable, not silent).
        waiver_log = a / "recall_waivers.jsonl"
        self.assertTrue(waiver_log.is_file())
        rows = [json.loads(ln) for ln in
                waiver_log.read_text(encoding="utf-8").splitlines() if ln.strip()]
        self.assertTrue(any(r["verdict"] == "solidity-recall-corpus-absent"
                            for r in rows))

    def test_no_corpus_no_source_is_trivially_ok(self):
        """An empty .auditooor-only ws (no source, no corpus) has nothing to
        floor and passes trivially - this keeps a deep-evidence-only honest-0
        from being blocked by an absent recall corpus."""
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        ok, detail, fp = HZV._check_recall_floor(ws)
        self.assertTrue(ok, detail)
        self.assertIn("nothing to floor", detail)

    def test_env_floor_override(self):
        """AUDITOOOR_HZ_RECALL_FLOOR retunes the floor."""
        ws = Path(tempfile.mkdtemp())
        _write_hunt_records(ws, _records("solidity", 3, 10))  # 30%
        ok_default, _, _ = HZV._check_recall_floor(ws)
        self.assertFalse(ok_default, "30% < 50% default must fail")
        os.environ["AUDITOOOR_HZ_RECALL_FLOOR"] = "0.2"
        try:
            ok_lo, detail, _ = HZV._check_recall_floor(ws)
            self.assertTrue(ok_lo, f"30% >= 20% must pass: {detail}")
        finally:
            del os.environ["AUDITOOOR_HZ_RECALL_FLOOR"]

    def test_recall_floor_wired_into_verify(self):
        """recall_floor appears as a named check in verify() output and can
        independently FAIL the verdict."""
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        _write_hunt_records(ws, _records("solidity", 1, 10))  # 10% -> fail
        r = HZV.verify(ws)
        self.assertIn("recall_floor", r["checks"])
        self.assertFalse(r["checks"]["recall_floor"]["ok"])
        self.assertFalse(r["ok"])

    def test_recall_recomputed_not_read_from_file(self):
        """A hand-written recall number must be IGNORED: the floor is recomputed
        from the per-case records. Plant a fake high recall verdict file + low
        actual records -> still fails."""
        ws = Path(tempfile.mkdtemp())
        a = ws / ".auditooor"
        a.mkdir(parents=True, exist_ok=True)
        # a fake written verdict claiming 100% recall (must be ignored).
        (a / "recall_floor.json").write_text(json.dumps(
            {"recall": 1.0, "ok": True}), encoding="utf-8")
        _write_hunt_records(ws, _records("solidity", 1, 10))  # real 10%
        ok, detail, _fp = HZV._check_recall_floor(ws)
        self.assertFalse(ok, "the written 100% must not fake the recompute")


if __name__ == "__main__":
    unittest.main(verbosity=2)
