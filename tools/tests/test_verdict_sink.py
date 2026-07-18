#!/usr/bin/env python3
"""Guard tests for verdict-sink.py - the bridge that persists workflow/agent
hunt verdicts into canonical hunt_findings_sidecars so the gates + learning loop
credit them, and the companion that makes persistence non-optional."""
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("verdict_sink", ROOT / "tools" / "verdict-sink.py")
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


class TestCandidateExtraction(unittest.TestCase):
    def test_hunt_findings_list(self):
        r = {"lane": "x", "findings": [
            {"title": "T1", "file_line": "src/A.sol:10", "severity": "High",
             "rubric_row": "row", "exploit_mechanism": "mech", "confidence": "firm",
             "attacker_profit_nonself": "victim loses", "designed_or_oos_precheck": "not designed"},
        ]}
        recs = mod._candidates_from_result(r)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["kind"], "hunt")
        self.assertEqual(recs[0]["applies"], "yes")  # High -> yes
        self.assertEqual(recs[0]["severity"], "High")

    def test_adjudication_collapse_is_rule_out(self):
        r = {"final_verdict": "collapse", "severity": "collapse", "finding_title": "T",
             "rubric_row": "none", "reason": "designed-as-intended at X.sol:5", "escalation": "none"}
        recs = mod._candidates_from_result(r)
        self.assertEqual(recs[0]["applies"], "no")
        self.assertEqual(recs[0]["kind"], "adjudication")

    def test_adjudication_paste_ready_applies_yes(self):
        r = {"final_verdict": "paste-ready", "severity": "High", "finding_title": "T",
             "pre_submit_ready": True, "reason": "real"}
        recs = mod._candidates_from_result(r)
        self.assertEqual(recs[0]["applies"], "yes")
        self.assertTrue(recs[0]["pre_submit_ready"])

    def test_validation_schema(self):
        r = {"survives": False, "severity": "Medium", "value_sink": "NONE",
             "poc_result": "SOURCE-TRACE-ONLY", "kill_reason": "no value sink"}
        recs = mod._candidates_from_result(r)
        self.assertEqual(recs[0]["applies"], "no")
        self.assertEqual(recs[0]["kind"], "validation")

    def test_generic_verdict_schema(self):
        r = {"verdict": "collapse", "bug": "B", "severity_candidate": "High",
             "value_sink": "x.rs:1", "kill_reason_if_any": "R45"}
        recs = mod._candidates_from_result(r)
        self.assertEqual(recs[0]["applies"], "no")


class TestSidecarEmission(unittest.TestCase):
    def setUp(self):
        self.ws = Path(tempfile.mkdtemp())
        (self.ws / "src").mkdir()
        self.f = self.ws / "src" / "Vault.sol"
        self.f.write_text("\n".join(f"// line {i}" for i in range(1, 60)))

    def test_emit_with_explicit_workspace_path(self):
        rec = {"title": "reentrancy", "file_line": "src/Vault.sol:10", "severity": "High",
               "applies": "yes", "confidence": "firm", "rubric": "Theft", "finding_text": "exploit",
               "attacker_path": "victim funds", "defending": "", "provider": "sonnet-via-agent",
               "poc_result": "", "kind": "hunt", "workspace_path": str(self.ws)}
        built = mod.build_sidecar(rec, "run1")
        self.assertIsNotNone(built)
        out, sc = built
        self.assertEqual(sc["workspace_path"], str(self.ws))
        self.assertEqual(sc["function_anchor"]["file"], "src/Vault.sol")
        self.assertEqual(sc["function_anchor"]["line"], 10)
        self.assertEqual(sc["result"]["applies_to_target"], "yes")
        # file:line resolves to a real line -> tier-2 source verified
        self.assertEqual(sc["verification_tier"], "tier-2-source-verified")

    def test_rule_out_carries_file_line_in_defending(self):
        # A source-cited rule-out must surface its file:line in defending_lines
        # so the function-coverage gate credits it as FP-defended (not hollow).
        rec = {"title": "view-only", "file_line": "src/Vault.sol:20", "severity": "Low",
               "applies": "no", "confidence": "high", "rubric": "n/a", "finding_text": "",
               "attacker_path": "", "defending": "pure view getter", "provider": "sonnet-via-agent",
               "poc_result": "", "kind": "validation", "workspace_path": str(self.ws)}
        out, sc = mod.build_sidecar(rec, "run1")
        self.assertEqual(sc["result"]["applies_to_target"], "no")
        self.assertIn("src/Vault.sol:20", sc["result"]["defending_lines"])

    def test_unverifiable_file_not_auto_promoted(self):
        # R76: a cited file that does not exist -> status needs-source-verification,
        # applies copied as-is, NOT auto-promoted.
        rec = {"title": "ghost", "file_line": "src/DoesNotExist.sol:5", "severity": "High",
               "applies": "yes", "confidence": "firm", "rubric": "Theft", "finding_text": "x",
               "attacker_path": "y", "defending": "", "provider": "sonnet-via-agent",
               "poc_result": "", "kind": "hunt", "workspace_path": str(self.ws)}
        out, sc = mod.build_sidecar(rec, "run1")
        self.assertEqual(sc["status"], "needs-source-verification")
        self.assertEqual(sc["verification_tier"], "tier-4-unverified")

    def test_idempotent_id(self):
        rec = {"title": "t", "file_line": "src/Vault.sol:1", "severity": "High", "applies": "yes",
               "kind": "hunt", "workspace_path": str(self.ws)}
        a = mod.build_sidecar(rec, "run1")[0].name
        b = mod.build_sidecar(rec, "run2")[0].name  # different run, same content -> same id
        self.assertEqual(a, b)

    def test_no_workspace_returns_none(self):
        mod._WS_HINT = None
        rec = {"title": "t", "file_line": "totallyrelative.xyz", "severity": "High",
               "applies": "yes", "kind": "hunt"}
        self.assertIsNone(mod.build_sidecar(rec, "run1"))


class TestTopLevelCorpusTokens(unittest.TestCase):
    """FIX(A): the sink sidecar must expose verdict/severity tokens at the TOP
    LEVEL so the learning ETL classifies it (CONFIRMED -> INV+detector,
    collapse/kill -> known-dead-end)."""

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp())
        (self.ws / "src").mkdir()
        (self.ws / "src" / "Vault.sol").write_text("\n".join(f"// l{i}" for i in range(1, 60)))

    def test_confirmed_surfaces_top_level_severity(self):
        rec = {"title": "theft", "file_line": "src/Vault.sol:10", "severity": "High",
               "applies": "yes", "confidence": "firm", "rubric": "Theft", "finding_text": "x",
               "attacker_path": "victim funds", "defending": "", "provider": "sonnet-via-agent",
               "poc_result": "", "kind": "hunt", "workspace_path": str(self.ws)}
        _, sc = mod.build_sidecar(rec, "run1")
        self.assertEqual(sc["proposed_severity"], "High")
        self.assertNotIn("KILL", sc["verdict"].upper())

    def test_rule_out_surfaces_top_level_kill_token(self):
        rec = {"title": "view", "file_line": "src/Vault.sol:20", "severity": "collapse",
               "applies": "no", "confidence": "high", "rubric": "n/a", "finding_text": "",
               "attacker_path": "", "defending": "pure view", "provider": "opus-adjudicator",
               "poc_result": "", "kind": "adjudication", "final_verdict": "collapse",
               "workspace_path": str(self.ws)}
        _, sc = mod.build_sidecar(rec, "run1")
        self.assertIn("KILLED", sc["verdict"].upper())
        self.assertIn("COLLAPSE", sc["verdict"].upper())
        self.assertEqual(sc["proposed_severity"], "")  # a kill is not a confirmed severity


class TestCorpusFeedbackClosure(unittest.TestCase):
    """FIX(A) end-to-end: sinking a CONFIRMED + a collapse verdict routes them into
    the corpus (INV + detector seed for the confirmed, known-dead-end for the
    collapse) via the learning ETL the sink now shells."""

    def test_sink_feeds_corpus_inv_detector_and_dead_end(self):
        tmp = Path(tempfile.mkdtemp())
        ws = tmp / "audits" / "feedchain"
        (ws / "src").mkdir(parents=True)
        (ws / "src" / "Pool.sol").write_text("\n".join(f"// l{i}" for i in range(1, 60)))
        # journal: one CONFIRMED hunt finding + one collapse adjudication
        journal = tmp / "journal.jsonl"
        journal.write_text("\n".join([
            json.dumps({"type": "result", "result": {
                "lane": "x", "findings": [
                    {"title": "drain via skipped guard", "file_line": "src/Pool.sol:10",
                     "severity": "High", "rubric_row": "Theft", "exploit_mechanism": "drain",
                     "confidence": "firm", "attacker_profit_nonself": "victim LP funds",
                     "designed_or_oos_precheck": "not designed"}]}}),
            json.dumps({"type": "result", "result": {
                "final_verdict": "collapse", "severity": "collapse",
                "finding_title": "double-spend in view", "file_line": "src/Pool.sol:20",
                "reason": "designed-as-intended; view getter at src/Pool.sol:20",
                "escalation": "none"}}),
        ]))
        # redirect corpus stores so the test never touches the real corpus
        kde = tmp / "reports" / "known_dead_ends.jsonl"
        inv_root = tmp / "derived" / "invariant_library_extended"
        det_root = tmp / "derived" / "detector_synthesis_v2"
        old = {k: os.environ.get(k) for k in
               ("AUDITOOOR_KDE_PATH", "AUDITOOOR_INV_BATCH_ROOT", "AUDITOOOR_DET_BATCH_ROOT")}
        os.environ["AUDITOOOR_KDE_PATH"] = str(kde)
        os.environ["AUDITOOOR_INV_BATCH_ROOT"] = str(inv_root)
        os.environ["AUDITOOOR_DET_BATCH_ROOT"] = str(det_root)
        try:
            rc = mod.main(["--journal", str(journal), "--run-id", "feed1",
                           "--workspace", str(ws), "--json"])
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        self.assertEqual(rc, 0)
        # the confirmed -> INV + detector seed in the derived dirs
        inv_files = list(inv_root.rglob("INV-*.yaml"))
        det_files = list(det_root.rglob("*.json"))
        self.assertTrue(inv_files, "no INV record emitted for the confirmed verdict")
        self.assertTrue(det_files, "no detector seed emitted for the confirmed verdict")
        # the collapse -> a known-dead-end row
        self.assertTrue(kde.exists(), "no known_dead_ends.jsonl written for the collapse verdict")
        kde_recs = [json.loads(l) for l in kde.read_text().splitlines() if l.strip()]
        self.assertTrue(kde_recs, "no known-dead-end record for the collapse verdict")
        self.assertTrue(all(r.get("schema_version") == "auditooor.known_dead_end.v1" for r in kde_recs))


class TestEndToEndJournal(unittest.TestCase):
    def test_journal_to_sidecars(self):
        ws = Path(tempfile.mkdtemp())
        (ws / "src").mkdir()
        (ws / "src" / "Refund.rs").write_text("\n".join(f"l{i}" for i in range(1, 30)))
        journal = ws / "journal.jsonl"
        journal.write_text("\n".join([
            json.dumps({"type": "started", "key": "k1"}),
            json.dumps({"type": "result", "key": "k1", "result": {
                "lane": "ni", "findings": [
                    {"title": "theft", "file_line": "src/Refund.rs:10", "severity": "High",
                     "rubric_row": "Stealing", "exploit_mechanism": "redirect", "confidence": "firm",
                     "attacker_profit_nonself": "victim BTC", "designed_or_oos_precheck": "not designed"}]}}),
        ]))
        rc = mod.main(["--journal", str(journal), "--run-id", "t", "--workspace", str(ws),
                       "--no-etl", "--json"])
        self.assertEqual(rc, 0)
        sidecars = list((ws / ".auditooor" / "hunt_findings_sidecars").glob("*.json"))
        self.assertEqual(len(sidecars), 1)
        sc = json.loads(sidecars[0].read_text())
        self.assertEqual(sc["result"]["applies_to_target"], "yes")
        self.assertEqual(sc["function_anchor"]["line"], 10)


if __name__ == "__main__":
    unittest.main(verbosity=2)
