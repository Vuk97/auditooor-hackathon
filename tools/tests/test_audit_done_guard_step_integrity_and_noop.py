#!/usr/bin/env python3
# <!-- r36-rebuttal: lane W3a-gate-wiring registered via agent-pathspec-register.py -->
"""W3a-gate-wiring: audit-done-guard.py must (1) wire readme-step-integrity so a
DEGRADED/SKIPPED required step blocks the done claim (a step that passes the
presence-only readme-conformance gate can still have run DEGRADED - the 6-day
local-git-only commit-mining miss), and (2) catch the verdict-feedback-noop state
(many ruled-out verdicts on disk, 0 banked into the known-dead-ends store - the
exact polygon pre-fix shape where the learning-loop sink never closed).

These tests exercise the NEW code paths directly + via evaluate():
  - _verdict_feedback_noop / _count_ruled_out_verdicts / _count_banked_dead_ends
  - the step-integrity wiring inside evaluate() (DEGRADED step -> NOT-DONE)
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
spec = importlib.util.spec_from_file_location("adg_w3a", str(_TOOLS / "audit-done-guard.py"))
m = importlib.util.module_from_spec(spec)
sys.modules["adg_w3a"] = m
spec.loader.exec_module(m)


def _ws() -> Path:
    ws = Path(tempfile.mkdtemp())
    (ws / ".auditooor").mkdir()
    return ws


def _fresh_marker(ws: Path, verdict: str = "pass-audit-complete", strict=True):
    (ws / ".auditooor" / "audit_completion.json").write_text(
        json.dumps({"verdict": verdict, "strict": strict}), encoding="utf-8")


def _paste_ready(ws: Path):
    pr = ws / "submissions" / "paste_ready"
    pr.mkdir(parents=True)
    (pr / "f.md").write_text("a finding")


def _pass_intermediate_gates(ws: Path):
    """Satisfy the gates that fire BETWEEN readme-conformance and step-integrity
    (skipped-test disposition, incomplete-guard-ack, multi-repo mining) so a test
    can reach the step-integrity / verdict-feedback-noop gates. Each accepts an
    empty/clean scan artifact as "ran, nothing to dispose"."""
    a = ws / ".auditooor"
    # skipped-test disposition: empty markers artifact = scan ran, nothing to dispose
    (a / "skipped_test_markers.jsonl").write_text("")
    # completeness-axis gate: waive the two terminal accounting axes that now
    # run before verdict-feedback-noop in audit-done-guard; they are unrelated
    # to this test lane and would otherwise mask the intended reason.
    (a / "audit_completeness_rebuttal.txt").write_text(
        "l37-rebuttal: coverage-map: not under test\n"
        "l37-rebuttal: rubric-coverage: not under test\n",
        encoding="utf-8",
    )


def _waive_all_conformance(ws: Path):
    """Waive every required README step so the presence-only readme-conformance
    gate passes - lets evaluate() reach the FULL-vs-DEGRADED step-integrity gate."""
    red = [
        "step-0a", "step-0b", "step-0c", "step-0d", "step-0e", "step-0f",
        "step-1", "step-2", "step-3", "step-4", "step-4b", "step-5",
    ]
    txt = "\n".join(f"waive: {s}: test fixture - not under test here" for s in red)
    (ws / ".auditooor" / "readme_step_waivers.txt").write_text(txt + "\n")


def _sidecar(ws: Path, rows):
    sd = ws / ".auditooor" / "hunt_findings_sidecars"
    sd.mkdir(parents=True, exist_ok=True)
    with (sd / "lane_a.jsonl").open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")


# --------------------------------------------------------------------------
# (2) verdict-feedback-noop - function-level (exact spec)
# --------------------------------------------------------------------------
class TestVerdictFeedbackNoop(unittest.TestCase):
    def test_many_ruled_out_zero_banked_is_noop(self):
        ws = _ws()
        _sidecar(ws, [{"unit_id": f"u{i}", "verdict": "ruled-out",
                       "reason": "no gap"} for i in range(60)])
        out = m._verdict_feedback_noop(ws)
        self.assertEqual(out["ruled_out"], 60)
        self.assertEqual(out["banked"], 0)
        self.assertTrue(out["noop"])

    def test_many_ruled_out_with_one_banked_passes(self):
        ws = _ws()
        _sidecar(ws, [{"unit_id": f"u{i}", "verdict": "rejected",
                       "reason": "fp"} for i in range(60)])
        # bank at least one dead end in the per-ws store
        (ws / ".auditooor" / "known_dead_ends.jsonl").write_text(
            json.dumps({"dead_end_id": "DE-x", "workspace": ws.name}) + "\n")
        out = m._verdict_feedback_noop(ws)
        self.assertEqual(out["ruled_out"], 60)
        self.assertGreaterEqual(out["banked"], 1)
        self.assertFalse(out["noop"])

    def test_below_threshold_passes(self):
        ws = _ws()
        _sidecar(ws, [{"unit_id": f"u{i}", "verdict": "drop",
                       "reason": "no gap"} for i in range(10)])
        out = m._verdict_feedback_noop(ws)
        self.assertEqual(out["ruled_out"], 10)
        self.assertFalse(out["noop"])  # below default 50

    def test_env_tunable_threshold(self):
        ws = _ws()
        _sidecar(ws, [{"unit_id": f"u{i}", "verdict": "drop",
                       "reason": "no gap"} for i in range(10)])
        old = os.environ.get("AUDIT_DONE_VERDICT_NOOP_MIN")
        os.environ["AUDIT_DONE_VERDICT_NOOP_MIN"] = "5"
        try:
            out = m._verdict_feedback_noop(ws)
            self.assertTrue(out["noop"])  # 10 >= 5, 0 banked
        finally:
            if old is None:
                os.environ.pop("AUDIT_DONE_VERDICT_NOOP_MIN", None)
            else:
                os.environ["AUDIT_DONE_VERDICT_NOOP_MIN"] = old

    def test_plausible_open_verdicts_are_not_ruled_out(self):
        ws = _ws()
        _sidecar(ws, [{"unit_id": f"u{i}", "verdict": "confirmed"}
                      for i in range(60)])
        out = m._verdict_feedback_noop(ws)
        self.assertEqual(out["ruled_out"], 0)
        self.assertFalse(out["noop"])


# --------------------------------------------------------------------------
# (2) verdict-feedback-noop - through evaluate() (blocks the done claim)
# --------------------------------------------------------------------------
import contextlib
import importlib.util as _ILU


@contextlib.contextmanager
def _step_integrity_clean(*, patch_integrity=True):
    """Make evaluate()'s freshly-loaded readme-step-integrity copy report no
    required steps (so it never blocks), letting the LATER verdict-feedback-noop
    gate fire. Offline, step-integrity's pin-freshness probe is unavoidably
    SKIPPED (no gh/network) and would block first; this isolates the noop gate.
    The noop LOGIC itself is proven precisely by TestVerdictFeedbackNoop."""
    orig = _ILU.spec_from_file_location

    def fake_spec(name, location, *a, **kw):
        sp = orig(name, location, *a, **kw)
        if name == "_rcc_done":
            real_exec = sp.loader.exec_module

            def patched_conformance(mod):
                real_exec(mod)
                mod.evaluate = lambda ws, strict=False: {
                    "conformance_pass": True, "red_step_ids": [], "steps": [],
                }
            sp.loader.exec_module = patched_conformance
        if name == "_rac_done":
            real_exec = sp.loader.exec_module

            def patched_attestation(mod):
                real_exec(mod)
                mod.verify = lambda ws, *args, **kwargs: {
                    "attestation_pass": True, "failures": [], "failed_step_ids": [],
                }
            sp.loader.exec_module = patched_attestation
        if name == "_rsi_done" and patch_integrity:
            real_exec = sp.loader.exec_module

            def patched_exec(mod):
                real_exec(mod)
                mod.STEPS = []  # no required steps -> nothing degraded/skipped
            sp.loader.exec_module = patched_exec
        return sp

    _ILU.spec_from_file_location = fake_spec
    try:
        yield
    finally:
        _ILU.spec_from_file_location = orig


class TestVerdictFeedbackNoopViaEvaluate(unittest.TestCase):
    def _happy_to_noop(self, ws: Path):
        _fresh_marker(ws)
        _paste_ready(ws)
        _waive_all_conformance(ws)
        _pass_intermediate_gates(ws)

    def test_noop_reason_surfaced_when_step_integrity_clean(self):
        ws = _ws()
        self._happy_to_noop(ws)
        _sidecar(ws, [{"unit_id": f"u{i}", "verdict": "ruled-out",
                       "reason": "no gap"} for i in range(60)])
        with _step_integrity_clean():
            r = m.evaluate(ws, ttl_hours=6)
        self.assertFalse(r["done"], r["reason"])
        self.assertIn("verdict-feedback-noop", r["reason"])
        self.assertTrue(
            any("verdict-feedback-noop" in g for g in r.get("fail_gates", [])),
            r.get("fail_gates"),
        )

    def test_noop_passes_with_one_banked_when_step_integrity_clean(self):
        ws = _ws()
        self._happy_to_noop(ws)
        _sidecar(ws, [{"unit_id": f"u{i}", "verdict": "ruled-out",
                       "reason": "no gap"} for i in range(60)])
        (ws / ".auditooor" / "known_dead_ends.jsonl").write_text(
            json.dumps({"dead_end_id": "DE-y", "workspace": ws.name}) + "\n")
        with _step_integrity_clean():
            r = m.evaluate(ws, ttl_hours=6)
        # the noop gate must NOT be the blocking reason (>=1 banked)
        self.assertNotIn("verdict-feedback-noop", r["reason"])


# --------------------------------------------------------------------------
# (1) step-integrity wiring - a DEGRADED step blocks the done claim
# --------------------------------------------------------------------------
class TestStepIntegrityWiredIntoDoneGuard(unittest.TestCase):
    def test_degraded_commit_mining_blocks_done(self):
        ws = _ws()
        _fresh_marker(ws)
        _paste_ready(ws)        # skips honest-zero
        _waive_all_conformance(ws)  # passes readme-conformance presence gate
        _pass_intermediate_gates(ws)
        # A commit-mining artifact that ran DEGRADED (local-git-only): it would
        # pass the presence-only conformance gate but readme-step-integrity must
        # classify it DEGRADED and the done-guard must now NOT-DONE on it.
        (ws / ".auditooor" / "git_commits_mining.json").write_text(
            json.dumps({"fallback_mode": "local-git-only", "commits_scanned": 12}))
        with _step_integrity_clean(patch_integrity=False):
            r = m.evaluate(ws, ttl_hours=6)
        self.assertFalse(r["done"], r["reason"])
        self.assertIn("step-integrity", r["reason"])
        self.assertTrue(
            any("commit-mining" in g for g in r.get("fail_gates", [])),
            r.get("fail_gates"),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
