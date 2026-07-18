#!/usr/bin/env python3
# <!-- r36-rebuttal: pathspec declared via tools/agent-pathspec-register.py lane LANE-PR3b-capability-publisher; orchestrator commits; sibling files untouched -->
"""Tests for tools/capability-metric-publisher.py.

synthetic_fixture: true

Covers:
  1. normalize_split  - held-out / heldout / fresh-target / fixed-ref / unknown.
  2. to_backtest_case - prefix vs fixed ref projection + field fallbacks.
  3. partition_cases / build_fixed_ref_controls - split routing + control derive.
  4. split_metrics    - strict line recall = CAUGHT/(CAUGHT+PARTIAL+MISSED),
                        file recall = (CAUGHT+PARTIAL)/scorable, na_rate.
  5. fixed_ref_metrics - CAUGHT/PARTIAL on a fixed ref = false positive.
  6. _gate            - None value -> NA (never a fake pass on 0 cases).
  7. assemble_report  - headline = HELD_OUT strict recall; TRAIN never headline.
  8. fresh_target_slot - not-run when no result dir; summarized when one exists.
  9. render_markdown  - renders without raising; TRAIN row carries the
                        "(circular - not finding power)" tag.
 10. _parse_backtest_stdout - tolerates leading log noise before the JSON.
 11. CLI end-to-end  - with a FAKE auditor-backtest.py stub on PATH-equivalent
                        (monkeypatched BACKTEST_TOOL) the publisher partitions,
                        runs, aggregates, writes latest.{json,md}, exits 0.
 12. strict-ci gate breach -> exit 1 (held-out FP / na thresholds).

The backtest subprocess is replaced by a STUB script written to a tempfile so
the test never depends on slither/yaml or network. The stub emits the same
{schema, cases:[...]} JSON auditor-backtest.py --json emits.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "capability-metric-publisher.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("capability_metric_publisher",
                                                  MODULE_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


CMP = _load_module()


# A stub backtest script: reads --cases JSONL, emits one CAUGHT/PARTIAL/MISSED/NA
# per case driven by the case id prefix, so tests deterministically control the
# outcome distribution without slither. Honors --local-checkout (ignored) and
# --corpus-detector-dir (ignored) so flag-passing does not break it.
STUB_BACKTEST = textwrap.dedent(r'''
    import json, sys, argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--local-checkout")
    ap.add_argument("--corpus-detector-dir", action="append", default=[])
    a, _ = ap.parse_known_args()
    out = []
    for raw in open(a.cases):
        raw = raw.strip()
        if not raw:
            continue
        c = json.loads(raw)
        cid = c.get("id", "")
        if cid.startswith("CAUGHT"):
            o = "CAUGHT"
        elif cid.startswith("PARTIAL"):
            o = "PARTIAL"
        elif cid.startswith("MISSED"):
            o = "MISSED"
        else:
            o = "NA"
        out.append({"schema": "auditooor.auditor_backtest.v1", "id": cid,
                    "repo": c.get("repo",""), "prefix_ref": c.get("prefix_ref",""),
                    "vuln_class": c.get("vuln_class",""),
                    "file_line": c.get("file_line",""),
                    "outcome": o, "caught_by": [], "fired_at_line": None,
                    "layers": {}, "missing_capability": None, "reason": ""})
    # leading log noise on purpose to exercise the tolerant parser
    print("[stub-backtest] some log line")
    print(json.dumps({"schema":"auditooor.auditor_backtest.v1","cases":out}))
''')


def _write_stub(tmp):
    p = Path(tmp) / "stub_backtest.py"
    p.write_text(STUB_BACKTEST)
    return p


class TestNormalizeSplit(unittest.TestCase):
    def test_heldout_variants(self):
        for v in ("HELD_OUT", "held-out", "heldout", "HoldOut"):
            self.assertEqual(CMP.normalize_split(v), "HELD_OUT")

    def test_fresh_and_fixed(self):
        self.assertEqual(CMP.normalize_split("fresh-target"), "FRESH_TARGET")
        self.assertEqual(CMP.normalize_split("fixed_ref"), "FIXED_REF")
        self.assertEqual(CMP.normalize_split("negative_control"), "FIXED_REF")

    def test_unknown_defaults_to_train(self):
        # an unlabeled case must NOT silently inflate held-out
        self.assertEqual(CMP.normalize_split(""), "TRAIN")
        self.assertEqual(CMP.normalize_split(None), "TRAIN")
        self.assertEqual(CMP.normalize_split("train"), "TRAIN")
        self.assertEqual(CMP.normalize_split("dev"), "DEV")


class TestProjection(unittest.TestCase):
    def test_prefix_ref_projection(self):
        c = {"case_id": "X1", "repo_url": "o/r",
             "vulnerable_ref_full_sha": "deadbeef",
             "attack_class": "reentrancy", "vuln_file": "src/V.sol",
             "vuln_line_start": 42}
        bt = CMP.to_backtest_case(c, ref_key="prefix")
        self.assertEqual(bt["id"], "X1")
        self.assertEqual(bt["repo"], "o/r")
        self.assertEqual(bt["prefix_ref"], "deadbeef")
        self.assertEqual(bt["vuln_class"], "reentrancy")
        self.assertEqual(bt["file_line"], "src/V.sol:42")

    def test_fixed_ref_projection(self):
        c = {"id": "X2", "repo": "o/r", "prefix_ref": "bad",
             "fixed_ref_full_sha": "good", "vuln_class": "oracle",
             "file_line": "a.sol:1"}
        bt = CMP.to_backtest_case(c, ref_key="fixed")
        self.assertEqual(bt["prefix_ref"], "good")  # fixed ref drives control

    def test_has_fixed_ref(self):
        self.assertTrue(CMP.has_fixed_ref({"fixed_ref": "abc"}))
        self.assertTrue(CMP.has_fixed_ref({"negative_control_ref": "abc"}))
        self.assertFalse(CMP.has_fixed_ref({"prefix_ref": "abc"}))


class TestPartition(unittest.TestCase):
    def test_partition_and_controls(self):
        cases = [
            {"id": "A", "split": "TRAIN"},
            {"id": "B", "split": "held-out"},
            {"id": "C", "split": "DEV", "fixed_ref": "good"},
            {"id": "D", "split": "fresh-target"},
            {"id": "E"},  # unlabeled -> TRAIN
        ]
        parts = CMP.partition_cases(cases)
        self.assertEqual([c["id"] for c in parts["TRAIN"]], ["A", "E"])
        self.assertEqual([c["id"] for c in parts["HELD_OUT"]], ["B"])
        self.assertEqual([c["id"] for c in parts["DEV"]], ["C"])
        self.assertEqual([c["id"] for c in parts["FRESH_TARGET"]], ["D"])
        controls = CMP.build_fixed_ref_controls(cases, [])
        # only C carries a fixed ref
        self.assertEqual([c["id"] for c in controls], ["C"])


class TestMetrics(unittest.TestCase):
    def _recs(self, *outcomes):
        return [{"outcome": o, "vuln_class": "reentrancy"} for o in outcomes]

    def test_strict_and_file_recall(self):
        m = CMP.split_metrics(self._recs("CAUGHT", "PARTIAL", "MISSED", "NA"))
        self.assertEqual(m["scorable"], 3)
        self.assertEqual(m["total"], 4)
        self.assertAlmostEqual(m["strict_line_recall"], 1/3)
        self.assertAlmostEqual(m["file_recall"], 2/3)
        self.assertAlmostEqual(m["na_rate"], 1/4)

    def test_empty_split_is_null_not_zero(self):
        m = CMP.split_metrics([])
        self.assertIsNone(m["strict_line_recall"])
        self.assertIsNone(m["na_rate"])
        self.assertEqual(m["scorable"], 0)

    def test_fixed_ref_fp(self):
        # CAUGHT/PARTIAL on a fixed ref = FP; MISSED = clean
        fx = CMP.fixed_ref_metrics(self._recs("CAUGHT", "PARTIAL", "MISSED", "NA"))
        self.assertEqual(fx["false_positives"], 2)
        self.assertEqual(fx["clean"], 1)
        self.assertEqual(fx["judged"], 3)
        self.assertAlmostEqual(fx["fixed_ref_fp_rate"], 2/3)

    def test_gate_none_is_na(self):
        g = CMP._gate("na_rate", None, 0.5, "<=", 0)
        self.assertEqual(g["status"], "NA")
        g2 = CMP._gate("na_rate", 0.2, 0.5, "<=", 10)
        self.assertEqual(g2["status"], "PASS")
        g3 = CMP._gate("na_rate", 0.9, 0.5, "<=", 10)
        self.assertEqual(g3["status"], "BREACH")


class TestAssembleAndRender(unittest.TestCase):
    def test_headline_is_heldout_not_train(self):
        split_recs = {
            "TRAIN": [{"outcome": "CAUGHT", "vuln_class": "x"}] * 10,   # 100% circular
            "DEV": [{"outcome": "MISSED", "vuln_class": "x"}],
            "HELD_OUT": [{"outcome": "CAUGHT", "vuln_class": "x"},
                         {"outcome": "MISSED", "vuln_class": "x"}],     # 50%
            "FRESH_TARGET": [],
        }
        fixed_recs = [{"outcome": "MISSED", "vuln_class": "x"}]
        fresh = {"status": "not-run", "note": "n", "result_path": None,
                 "proof_backed_lead_yield": None, "split_cases_seen": 0}
        rep = CMP.assemble_report(
            split_recs, fixed_recs, fresh,
            thresholds={"na_rate_max": 0.5, "fixed_ref_fp_max": 0.1,
                        "min_heldout_scorable": 0})
        # headline tracks HELD_OUT (0.5), NOT TRAIN (1.0)
        self.assertAlmostEqual(rep["headline"]["value"], 0.5)
        self.assertEqual(rep["headline"]["metric"], "HELD_OUT strict_line_recall")
        self.assertEqual(rep["headline"]["honest_status"], "measured")
        md = CMP.render_markdown(rep)
        self.assertIn("circular - not finding power", md)
        self.assertIn("HELD_OUT strict line recall", md)

    def test_fixed_ref_fp_gate_breach(self):
        split_recs = {"TRAIN": [], "DEV": [],
                      "HELD_OUT": [{"outcome": "CAUGHT", "vuln_class": "x"}],
                      "FRESH_TARGET": []}
        # one FP control -> 100% FP rate, over the 0.1 threshold
        fixed_recs = [{"outcome": "CAUGHT", "vuln_class": "x"}]
        fresh = {"status": "not-run", "note": "n", "result_path": None,
                 "proof_backed_lead_yield": None, "split_cases_seen": 0}
        rep = CMP.assemble_report(
            split_recs, fixed_recs, fresh,
            thresholds={"na_rate_max": 0.5, "fixed_ref_fp_max": 0.1,
                        "min_heldout_scorable": 0})
        self.assertEqual(rep["gate_status"], "BREACH")
        self.assertIn("fixed_ref_fp_rate", rep["gate_breaches"])


class TestFreshTargetSlot(unittest.TestCase):
    def test_not_run_when_missing(self):
        slot = CMP.fresh_target_slot(Path("/nonexistent/xyz"), 0)
        self.assertEqual(slot["status"], "not-run")
        self.assertIsNone(slot["result_path"])

    def test_summarized_when_present(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td) / "2026-05-29"
            d.mkdir(parents=True)
            (d / "result.json").write_text(json.dumps(
                {"proof_backed_lead_yield": 3}))
            slot = CMP.fresh_target_slot(Path(td), 1)
            self.assertEqual(slot["status"], "summarized")
            self.assertEqual(slot["proof_backed_lead_yield"], 3)


class TestParseStdout(unittest.TestCase):
    def test_tolerates_leading_noise(self):
        s = "[log] noise\nmore noise\n" + json.dumps(
            {"schema": "x", "cases": [{"id": "A", "outcome": "CAUGHT"}]})
        parsed = CMP._parse_backtest_stdout(s)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["id"], "A")

    def test_no_json_returns_none(self):
        self.assertIsNone(CMP._parse_backtest_stdout("no json here"))
        self.assertIsNone(CMP._parse_backtest_stdout(""))


class TestCliEndToEnd(unittest.TestCase):
    def test_full_pipeline_with_stub_backtest(self):
        with tempfile.TemporaryDirectory() as td:
            stub = _write_stub(td)
            # corpus: held-out has 1 CAUGHT + 1 MISSED = 50%; train all CAUGHT;
            # one DEV case carries a fixed ref -> a fixed-ref control. The stub
            # returns MISSED for a fixed-ref control id starting MISSED, so the
            # control is clean (no FP).
            cases = [
                {"id": "CAUGHT-train", "split": "TRAIN", "repo": "o/r",
                 "prefix_ref": "p", "vuln_class": "reentrancy"},
                {"id": "CAUGHT-held", "split": "held-out", "repo": "o/r",
                 "prefix_ref": "p", "vuln_class": "reentrancy"},
                {"id": "MISSED-held", "split": "held-out", "repo": "o/r",
                 "prefix_ref": "p", "vuln_class": "oracle"},
                {"id": "MISSED-ctrl", "split": "DEV", "repo": "o/r",
                 "prefix_ref": "p", "fixed_ref": "good", "vuln_class": "dos"},
            ]
            cf = Path(td) / "cases.jsonl"
            cf.write_text("\n".join(json.dumps(c) for c in cases) + "\n")
            out_dir = Path(td) / "out"

            # monkeypatch the backtest tool path to the stub
            orig = CMP.BACKTEST_TOOL
            CMP.BACKTEST_TOOL = stub
            try:
                rc = CMP.main([
                    "--cases", str(cf),
                    "--out-dir", str(out_dir),
                    "--fresh-target-dir", str(Path(td) / "nofresh"),
                    "--json",
                ])
            finally:
                CMP.BACKTEST_TOOL = orig

            self.assertEqual(rc, 0)
            self.assertTrue((out_dir / "latest.json").exists())
            self.assertTrue((out_dir / "latest.md").exists())
            rep = json.loads((out_dir / "latest.json").read_text())
            # held-out: 1 CAUGHT, 1 MISSED -> strict recall 0.5
            self.assertAlmostEqual(rep["headline"]["value"], 0.5)
            self.assertEqual(rep["splits"]["HELD_OUT"]["scorable"], 2)
            # train: 1 CAUGHT -> 100% but never the headline
            self.assertAlmostEqual(rep["splits"]["TRAIN"]["strict_line_recall"], 1.0)
            # fixed-ref control (MISSED-ctrl -> stub MISSED) = clean, 0% FP
            self.assertEqual(rep["fixed_ref"]["judged"], 1)
            self.assertEqual(rep["fixed_ref"]["false_positives"], 0)
            self.assertAlmostEqual(rep["fixed_ref"]["fixed_ref_fp_rate"], 0.0)
            self.assertEqual(rep["fresh_target"]["status"], "not-run")

    def test_strict_ci_exit_1_on_breach(self):
        with tempfile.TemporaryDirectory() as td:
            stub = _write_stub(td)
            # a fixed-ref control whose id starts CAUGHT -> stub returns CAUGHT
            # on the FIXED ref = a false positive -> breach with fp-max 0.0
            cases = [
                {"id": "CAUGHT-held", "split": "held-out", "repo": "o/r",
                 "prefix_ref": "p", "vuln_class": "reentrancy"},
                {"id": "CAUGHT-ctrl", "split": "DEV", "repo": "o/r",
                 "prefix_ref": "p", "fixed_ref": "good", "vuln_class": "dos"},
            ]
            cf = Path(td) / "cases.jsonl"
            cf.write_text("\n".join(json.dumps(c) for c in cases) + "\n")
            out_dir = Path(td) / "out"
            orig = CMP.BACKTEST_TOOL
            CMP.BACKTEST_TOOL = stub
            try:
                rc = CMP.main([
                    "--cases", str(cf), "--out-dir", str(out_dir),
                    "--fresh-target-dir", str(Path(td) / "nofresh"),
                    "--fixed-ref-fp-max", "0.0",
                    "--strict-ci",
                ])
            finally:
                CMP.BACKTEST_TOOL = orig
            self.assertEqual(rc, 1)
            rep = json.loads((out_dir / "latest.json").read_text())
            self.assertEqual(rep["gate_status"], "BREACH")
            self.assertIn("fixed_ref_fp_rate", rep["gate_breaches"])


if __name__ == "__main__":
    unittest.main()
