#!/usr/bin/env python3
# <!-- r36-rebuttal: lane AUDIT-COMPLETENESS-SCHEMA-FIX registered in .auditooor/agent_pathspec.json -->
"""NUVA 2026-06-30 serving-join fixes in audit-completeness-check.py:

1. check_audit_preflight: the per-function-invariant manifest emits `function_count`
   (+ a `functions` LIST), not a bare `count`; and the canonical per-function
   preflight worklist is `per_fn_hacker_questions.jsonl` (per_fn, not per_function).
   Both were missed -> a genuine preflight read as HOLLOW.

2. check_chain_synth: the current report schema carries processed-input evidence in
   `summary` (detector_cluster_count / exploit_angle_count / ...) + `submission_posture`,
   not the legacy `chains_synthesized`/`matched_templates` fields -> an honest
   0-chains-over-processed-input run read as HOLLOW.

NEVER-FALSE-PASS: a truly empty manifest / empty summary / no-posture artifact still
reads hollow (no positive count, no list, no posture string).
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "audit-completeness-check.py"


def _load():
    spec = importlib.util.spec_from_file_location("acc_schema", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["acc_schema"] = m
    spec.loader.exec_module(m)
    return m


acc = _load()


def _wj(p: Path, obj):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


class PreflightManifestSchemaTest(unittest.TestCase):
    def test_function_count_manifest_credits(self):
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t)
            _wj(ws / ".auditooor" / "per_function_invariants" / "manifest.json",
                {"function_count": 65, "functions": [{"function": "deposit"}]})
            r = acc.check_audit_preflight(ws)
            self.assertTrue(r.ok, f"function_count manifest must credit; got {r.reason}")

    def test_empty_manifest_still_hollow_under_strict(self):
        import os
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t)
            _wj(ws / ".auditooor" / "per_function_invariants" / "manifest.json",
                {"function_count": 0, "functions": []})
            os.environ["AUDITOOOR_L37_STRICT"] = "1"
            try:
                r = acc.check_audit_preflight(ws)
            finally:
                os.environ.pop("AUDITOOOR_L37_STRICT", None)
            self.assertFalse(r.ok, "empty manifest must stay hollow under strict (never-false-pass)")


class ChainSynthSummarySchemaTest(unittest.TestCase):
    def test_summary_processed_input_credits(self):
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t)
            _wj(ws / ".auditooor" / "chain_synthesis_2026-06-29.json",
                {"schema_version": 1, "plans": [], "advisory_only": True,
                 "submission_posture": "candidate_not_submit_ready",
                 "summary": {"detector_cluster_count": 30, "exploit_angle_count": 5}})
            r = acc.check_chain_synth(ws)
            self.assertTrue(r.ok, f"summary processed-input must credit; got {r.reason}")

    def test_empty_summary_no_posture_still_hollow_under_strict(self):
        import os
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t)
            _wj(ws / ".auditooor" / "chain_synthesis_2026-06-29.json",
                {"schema_version": 1, "plans": [], "summary": {}})
            os.environ["AUDITOOOR_L37_STRICT"] = "1"
            try:
                r = acc.check_chain_synth(ws)
            finally:
                os.environ.pop("AUDITOOOR_L37_STRICT", None)
            self.assertFalse(r.ok, "empty summary + no posture must stay hollow under strict")


if __name__ == "__main__":
    unittest.main(verbosity=2)
