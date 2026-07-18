"""Loop-fix 2026-06-22: audit-completeness-check.check_chain_synth selected the wrong
artifact. The two-glob (chain_synthesis*.json + chain_synth*.json) + dedup-by-insertion
left an auxiliary sidecar (chain_synth_source_links.json) as reports[-1], so a
genuinely-ran chain-synth (status=blocked-missing-hop-evidence, matched_templates=10) was
false-flagged HOLLOW. Fix: prefer chain_synthesis_*.json (the real report) + pick freshest
by mtime. A truly hollow {} artifact must still fail under strict (no false-pass regress).
"""
import importlib.util
import json
import os
import sys
import time
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location("acc_cs", str(_TOOLS / "audit-completeness-check.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["acc_cs"] = mod
    spec.loader.exec_module(mod)
    return mod


class TestChainSynthReportSelection(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def _ws(self, files):
        ws = Path(tempfile.mkdtemp()).resolve()
        (ws / ".auditooor").mkdir(parents=True)
        for name, payload in files:
            p = ws / ".auditooor" / name
            p.write_text(json.dumps(payload))
        return ws

    def test_picks_real_report_over_sidecar(self):
        ws = self._ws([
            ("chain_synth_source_links.json", {"links": []}),  # sidecar, no verdict fields
            ("chain_synthesis_2026-06-22.json", {
                "chains_synthesized": 0, "matched_templates": 10, "proof_obligations": 10,
                "status": "blocked-missing-hop-evidence",
                "input_counts": {"current_queue_leads": 28945}}),
        ])
        r = self.m.check_chain_synth(ws)
        self.assertEqual(r.detail.get("evaluated_artifact"), "chain_synthesis_2026-06-22.json")
        self.assertTrue(r.ok, "genuinely-ran chain-synth (blocked-* ran-state) must PASS")

    def test_picks_real_report_over_fresher_planner_artifact(self):
        # The chained-attack-planner writes its hollow advisory output to a
        # chain_synthesis_<date>.json filename that collides with the genuine report
        # and is FRESHER. The gate must still evaluate the genuine chain-synth-schema
        # report, not the fresher planner artifact (near-intents 2026-06-26).
        ws = self._ws([
            ("chain_synthesis_2026-06-24.json", {
                "schema": "auditooor.chain_synthesis_report.v1",
                "chains_synthesized": 0, "matched_templates": 10, "proof_obligations": 10,
                "status": "blocked-missing-hop-evidence",
                "input_counts": {"current_queue_leads": 7820}}),
            ("chain_synthesis_2026-06-25.json", {
                "schema_version": "auditooor.chained_attack_plans.v1",
                "advisory_only": True, "plans": [], "summary": {"plan_count": 0}}),
        ])
        old = ws / ".auditooor" / "chain_synthesis_2026-06-24.json"
        new = ws / ".auditooor" / "chain_synthesis_2026-06-25.json"
        os.utime(old, (1000, 1000))
        os.utime(new, (2000, 2000))  # planner artifact strictly fresher
        r = self.m.check_chain_synth(ws)
        self.assertEqual(r.detail.get("evaluated_artifact"), "chain_synthesis_2026-06-24.json")
        self.assertTrue(r.ok, "genuine chain-synth report must be evaluated, not the fresher planner artifact")

    def test_hollow_artifact_still_fails_strict(self):
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        try:
            ws = self._ws([("chain_synthesis_2026-06-22.json", {"chains_synthesized": 0})])
            r = self.m.check_chain_synth(ws)
            self.assertFalse(r.ok, "hollow {chains_synthesized:0} with no verdict must FAIL strict")
        finally:
            os.environ.pop("AUDITOOOR_L37_STRICT", None)


if __name__ == "__main__":
    unittest.main(verbosity=2)
