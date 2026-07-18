#!/usr/bin/env python3
# <!-- r36-rebuttal: lane L37-AUDIT-DONE-GUARD registered via agent-pathspec-register.py -->
"""Guard test: stale pass-marker must never outrank a fresh recomputed fail verdict.

Bug (medium, fixed 2026-06-14):
  production_pipeline_manifest.json stored l37_verdict="pass-audit-complete" from
  a prior run. audit_complete_last_result.json (the authoritative gate-written file)
  stored a fresh fail verdict. The guard incorrectly reported DONE because
  _verdict_blob() included "l37_verdict" as a pass-token source, and _find_marker()
  did not unconditionally prefer the authoritative audit_complete_last_result.json
  over older candidates.

Fixed by:
  1. Removing "l37_verdict" from _verdict_blob() - that field is a cached/derived
     value in production_pipeline_manifest.json and must not override the
     authoritative "verdict" field.
  2. _find_marker() now unconditionally prefers audit_complete_last_result.json
     (the file written by the gate tool itself) when it exists with a verdict,
     regardless of mtime, so a stale pass in another candidate cannot win.

This test pins:
  A. l37_verdict=pass in same file as verdict=fail  -> NOT-DONE (pre-fix: false-DONE)
  B. stale pass in audit_completion.json, fresh fail in audit_complete_last_result.json
     -> NOT-DONE (pre-fix: false-DONE because mtime tiebreaker could pick wrong file)
  C. fresh pass in audit_complete_last_result.json, old fail in audit_completion.json
     -> DONE (regression: authoritative marker must always win)
  D. production_pipeline_manifest l37_verdict=pass with no authoritative marker
     and audit_completion.json verdict=fail -> NOT-DONE (l37_verdict ignored)
  E. negative: fresh pass in audit_complete_last_result.json alone -> DONE (happy path)
"""
import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("adg_stale", str(_TOOLS / "audit-done-guard.py"))
m = importlib.util.module_from_spec(spec)
sys.modules["adg_stale"] = m
spec.loader.exec_module(m)


def _ws() -> Path:
    ws = Path(tempfile.mkdtemp())
    (ws / ".auditooor").mkdir()
    return ws


def _paste_ready(ws: Path) -> None:
    (ws / "submissions" / "paste_ready").mkdir(parents=True, exist_ok=True)
    (ws / "submissions" / "paste_ready" / "finding.md").write_text(
        "a finding", encoding="utf-8"
    )


class TestStalel37VerdictDoesNotOverrideFreshFail(unittest.TestCase):
    """Case A: marker has verdict=fail but l37_verdict=pass -> must be NOT-DONE."""

    def test_l37_verdict_pass_with_verdict_fail_is_not_done(self):
        ws = _ws()
        (ws / ".auditooor" / "audit_completion.json").write_text(
            json.dumps({
                "verdict": "fail-no-tier6-mining",
                "l37_verdict": "pass-audit-complete",
                "strict": True,
            }),
            encoding="utf-8",
        )
        _paste_ready(ws)
        r = m.evaluate(ws, ttl_hours=6)
        self.assertFalse(r["done"], "l37_verdict=pass must not override verdict=fail")
        self.assertIn("NOT pass-audit-complete", r["reason"])

    def test_l37_verdict_pass_in_last_result_with_verdict_fail_is_not_done(self):
        ws = _ws()
        # Simulate a marker file that contains both a fail verdict AND a stale
        # l37_verdict pass (e.g., if an older tool version wrote this combination).
        (ws / ".auditooor" / "audit_complete_last_result.json").write_text(
            json.dumps({
                "verdict": "fail-no-chain-synth",
                "l37_verdict": "pass-audit-complete",
                "strict": True,
            }),
            encoding="utf-8",
        )
        _paste_ready(ws)
        r = m.evaluate(ws, ttl_hours=6)
        self.assertFalse(r["done"], "l37_verdict pass must not override verdict fail in authoritative marker")
        self.assertIn("NOT pass-audit-complete", r["reason"])


class TestAuthoritativeMarkerPreference(unittest.TestCase):
    """Case B/C: audit_complete_last_result.json must be preferred unconditionally."""

    def test_stale_pass_in_old_marker_fresh_fail_in_authoritative_is_not_done(self):
        # audit_completion.json (older) has pass; audit_complete_last_result.json
        # (authoritative gate-written file) has a fresh fail -> must be NOT-DONE.
        ws = _ws()
        old = ws / ".auditooor" / "audit_completion.json"
        old.write_text(
            json.dumps({"verdict": "pass-audit-complete", "strict": True}),
            encoding="utf-8",
        )
        # Force old marker's mtime to be very recent (would win under pure mtime logic)
        now = time.time()
        os.utime(old, (now + 1, now + 1))

        authoritative = ws / ".auditooor" / "audit_complete_last_result.json"
        authoritative.write_text(
            json.dumps({"verdict": "fail-no-tier6-mining", "strict": True}),
            encoding="utf-8",
        )

        _paste_ready(ws)
        r = m.evaluate(ws, ttl_hours=6)
        self.assertFalse(
            r["done"],
            "Authoritative marker (audit_complete_last_result.json) fail must override "
            "stale pass in audit_completion.json even when audit_completion.json has a "
            "newer mtime",
        )
        self.assertIn("NOT pass-audit-complete", r["reason"])
        # The reason must mention the authoritative file, not the old marker
        self.assertIn("audit_complete_last_result.json", r["reason"])

    def test_fresh_pass_in_authoritative_old_fail_in_old_marker_is_done(self):
        # audit_completion.json (older) has fail; audit_complete_last_result.json
        # (authoritative) has a fresh pass -> must be DONE.
        ws = _ws()
        old = ws / ".auditooor" / "audit_completion.json"
        old.write_text(
            json.dumps({"verdict": "fail-no-tier6-mining", "strict": True}),
            encoding="utf-8",
        )

        authoritative = ws / ".auditooor" / "audit_complete_last_result.json"
        authoritative.write_text(
            json.dumps({"verdict": "pass-audit-complete", "strict": True}),
            encoding="utf-8",
        )

        _paste_ready(ws)
        r = m.evaluate(ws, ttl_hours=6)
        self.assertTrue(
            r["done"],
            "Authoritative marker (audit_complete_last_result.json) fresh pass must "
            "result in DONE even when audit_completion.json has an older fail",
        )


class TestPipelineManifestL37VerdictIgnored(unittest.TestCase):
    """Case D: l37_verdict in a file is never a valid pass-token source."""

    def test_fail_verdict_with_l37_pass_not_done_regardless_of_paste_ready(self):
        # This is the exact morpho-midnight scenario from the bug report:
        # production_pipeline_manifest recorded l37_verdict=pass-audit-complete from
        # an older run; audit_complete_last_result.json has a fresh fail.
        # Guard must NOT be fooled by l37_verdict.
        ws = _ws()
        # Write the authoritative marker with a fail verdict
        (ws / ".auditooor" / "audit_complete_last_result.json").write_text(
            json.dumps({
                "schema": "auditooor.audit_completeness_check.v1",
                "gate": "L37-AUDIT-COMPLETENESS",
                "verdict": "fail-no-chain-synth",
                "strict": True,
                "failures": ["fail-no-chain-synth"],
                "rebutted": [],
                "workspace": str(ws),
            }),
            encoding="utf-8",
        )
        # Simulate a stale production_pipeline_manifest.json (NOT a marker candidate,
        # but historically the bug was triggered when l37_verdict leaked into the
        # verdict blob check via a different marker that included l37_verdict).
        (ws / ".auditooor" / "production_pipeline_manifest.json").write_text(
            json.dumps({
                "schema": "auditooor.pr10_production_pipeline.v1",
                "verdict": "pass-production-pipeline-complete",
                "l37_verdict": "pass-audit-complete",  # stale cached pass
                "generated_at": "2026-06-01T00:00:00Z",
            }),
            encoding="utf-8",
        )
        _paste_ready(ws)
        r = m.evaluate(ws, ttl_hours=6)
        self.assertFalse(r["done"], "stale l37_verdict in pipeline manifest must not cause DONE")
        self.assertIn("NOT pass-audit-complete", r["reason"])

    def test_fail_verdict_blob_has_no_pass_audit_complete_from_l37_verdict(self):
        # Directly verify _verdict_blob no longer includes l37_verdict in its output.
        obj = {
            "verdict": "fail-no-tier6-mining",
            "l37_verdict": "pass-audit-complete",
            "status": "running",
        }
        blob = m._verdict_blob(obj)
        self.assertNotIn("pass-audit-complete", blob,
                         "_verdict_blob must not surface l37_verdict as a pass-token source")
        self.assertIn("fail-no-tier6-mining", blob,
                      "_verdict_blob must include the authoritative verdict field")


class TestAuthoritativeMarkerHappyPath(unittest.TestCase):
    """Case E: fresh pass in audit_complete_last_result.json alone -> DONE."""

    def test_fresh_pass_in_authoritative_marker_alone_is_done(self):
        ws = _ws()
        (ws / ".auditooor" / "audit_complete_last_result.json").write_text(
            json.dumps({"verdict": "pass-audit-complete", "strict": True}),
            encoding="utf-8",
        )
        _paste_ready(ws)
        r = m.evaluate(ws, ttl_hours=6)
        self.assertTrue(r["done"], r["reason"])

    def test_no_authoritative_marker_falls_back_to_audit_completion(self):
        # When audit_complete_last_result.json does not exist, the guard falls back
        # to the regular marker candidates (existing behavior preserved).
        ws = _ws()
        (ws / ".auditooor" / "audit_completion.json").write_text(
            json.dumps({"verdict": "pass-audit-complete", "strict": True}),
            encoding="utf-8",
        )
        _paste_ready(ws)
        r = m.evaluate(ws, ttl_hours=6)
        self.assertTrue(r["done"], r["reason"])

    def test_no_authoritative_marker_no_verdict_marker_not_done(self):
        ws = _ws()
        # Only audit_logs/audit_completion.json with no verdict field (toolchain hash
        # schema). The guard falls back to this file as a candidate but finds no
        # pass-audit-complete verdict in it.
        (ws / ".audit_logs").mkdir()
        (ws / ".audit_logs" / "audit_completion.json").write_text(
            json.dumps({
                "schema": "auditooor.audit_completion.v1",
                "completed_at": time.time(),
                "commit_sha": "abc1234",
            }),
            encoding="utf-8",
        )
        r = m.evaluate(ws, ttl_hours=6)
        self.assertFalse(r["done"])
        # The file exists but carries no pass-audit-complete verdict.
        self.assertFalse(r["done"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
