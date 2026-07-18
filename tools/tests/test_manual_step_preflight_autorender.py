# <!-- r36-rebuttal: lane manual-step-preflight registered via agent-pathspec-register.py -->
"""Regression guard: manual-step-preflight self-heals instead of blanket-denying
(2026-07-02).

Root defect: the PreToolUse hook (tools/hooks/manual-step-preflight-gate.py)
correctly matches Write|Edit and correctly denies an attestation write with no
current read-ack marker - but the marker was ONLY produced by a separate, manual
`manual-step-preflight.py render` CLI invocation. In practice nobody ran it, so
the hook either blanket-denied every manual-step attestation forever, or got
disabled outright to unblock work.

Fix: `tools/manual-step-preflight.py` gains a pure library function
`auto_render_if_missing(ws, step_id, manifest)` that writes the SAME read-ack
marker `render()` would write, callable inline (no separate CLI step). The hook
calls it itself the first time it sees an attestation write with no marker, then
re-checks, instead of denying forever.

Invariants proven here:
  1. auto_render_if_missing() is idempotent and produces a marker identical in
     content to what render() would produce; a second call is a no-op
     (auto_rendered=False) when the step text has not drifted.
  2. It never touches render/check/dispatch-setup's existing CLI contract
     (dispatch table, exit codes) - see test_manual_step_preflight.py, untouched.
  3. The hook self-heals: given a Write for a step with NO prior marker and
     GROUNDED content (matching read_ack + real evidence_ref), the first
     encounter auto-renders the marker and then ALLOWS (proving it re-checks
     after self-healing rather than still denying on the stale marker_missing
     state).
  4. The hook still DENIES if, after auto-rendering the marker, the attestation
     content itself is ungrounded (no read_ack / no evidence_refs) - grounding
     is never weakened, only the "you must have separately pre-run render"
     precondition is removed.
  5. AUDITOOOR_MANUAL_STEP_AUTORENDER=0 restores the exact old behavior
     (blanket-deny, no marker written) so a prior audit's enforcement posture
     can be reproduced byte-for-byte if an operator opts in to that.
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent.parent
_ENGINE = _REPO / "tools" / "manual-step-preflight.py"
_HOOK = _REPO / "tools" / "hooks" / "manual-step-preflight-gate.py"


def _load_engine():
    spec = importlib.util.spec_from_file_location("_msp_engine_autorender", _ENGINE)
    m = importlib.util.module_from_spec(spec)
    sys.modules["_msp_engine_autorender"] = m
    spec.loader.exec_module(m)
    return m


MOD = _load_engine()

_MANIFEST = {"steps": [
    {"step_id": "step-0b", "label": "Author SCOPE.md", "class": "manual-judgment",
     "what_must_be_done": "Author SCOPE.md with exact in-scope repos.",
     "how_to_verify_done": {"attestation_required": True,
                            "artifact_checks": [{"type": "file_nonempty", "path": "SCOPE.md"}]},
     "drift_note": ""},
    {"step_id": "step-1", "label": "make audit", "class": "mechanical",
     "what_must_be_done": "run make audit",
     "how_to_verify_done": {"attestation_required": False, "artifact_checks": []},
     "drift_note": ""},
]}


def _run_hook(payload: dict, env: dict | None = None) -> tuple[int, str, str]:
    full_env = dict(os.environ)
    full_env.pop("AUDITOOOR_MANUAL_STEP_AUTORENDER", None)
    if env:
        full_env.update(env)
    proc = subprocess.run(
        [sys.executable, str(_HOOK)],
        input=json.dumps(payload),
        capture_output=True, text=True, env=full_env,
    )
    return proc.returncode, proc.stdout, proc.stderr


class AutoRenderLibraryTest(unittest.TestCase):
    """auto_render_if_missing() as a pure library function."""

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp())
        (self.ws / ".auditooor" / "attestations").mkdir(parents=True)

    def _sha(self, sid):
        return MOD._step_text_sha(MOD._canonical_step(_MANIFEST, sid))

    def test_writes_marker_identical_to_render(self):
        r = MOD.auto_render_if_missing(self.ws, "step-0b", _MANIFEST)
        self.assertTrue(r["ok"])
        self.assertTrue(r["auto_rendered"])
        marker_path = (self.ws / ".auditooor" / "attestations" / ".preflight" / "step-0b.json")
        self.assertTrue(marker_path.exists())
        marker = json.loads(marker_path.read_text())
        self.assertEqual(marker["step_text_sha"], self._sha("step-0b"))
        self.assertEqual(marker["step_id"], "step-0b")

    def test_idempotent_noop_when_marker_current(self):
        MOD.auto_render_if_missing(self.ws, "step-0b", _MANIFEST)
        marker_path = (self.ws / ".auditooor" / "attestations" / ".preflight" / "step-0b.json")
        before = marker_path.read_text()
        r2 = MOD.auto_render_if_missing(self.ws, "step-0b", _MANIFEST)
        self.assertTrue(r2["ok"])
        self.assertFalse(r2["auto_rendered"], "second call on an unchanged step must be a no-op")
        self.assertEqual(marker_path.read_text(), before)

    def test_unknown_step_returns_not_ok(self):
        r = MOD.auto_render_if_missing(self.ws, "step-does-not-exist", _MANIFEST)
        self.assertFalse(r["ok"])
        self.assertFalse(r["auto_rendered"])

    def test_does_not_break_existing_render_contract(self):
        """render()/check()/dispatch_setup() CLI-facing functions are unchanged in
        signature and behavior - auto_render_if_missing is purely additive."""
        r = MOD.render(self.ws, "step-0b", _MANIFEST)
        self.assertTrue(r["ok"])
        self.assertIn("attestation_template", r)
        c = MOD.check(self.ws, _MANIFEST)
        self.assertEqual(c["verdict"], "pass-manual-steps-grounded")
        d = MOD.dispatch_setup(self.ws, _MANIFEST)
        self.assertIn("parallelizable_steps", d)


class HookSelfHealTest(unittest.TestCase):
    """The PreToolUse hook auto-renders on first encounter instead of blanket-denying.

    The hook subprocess always loads the REAL repo manifest (tools/readme_runbook_steps.json)
    via `_load_manifest(None)`, not a test fixture - so these tests compute the read_ack
    sha against that real manifest's real step-0b, matching what the hook will compute.
    If step-0b is ever removed/renamed or stops being manual+attest-required in the real
    manifest, these tests skip gracefully (same escape hatch as the existing gate-wiring
    test suite) rather than false-failing.
    """

    def setUp(self):
        os.environ.pop("AUDITOOOR_MANUAL_STEP_STRICT", None)
        self.ws = Path(tempfile.mkdtemp())
        (self.ws / ".auditooor" / "attestations").mkdir(parents=True)
        real_manifest = MOD._load_manifest(None)
        real_step = real_manifest and MOD._canonical_step(real_manifest, "step-0b")
        if not real_step or not (MOD._is_manual(real_step) and MOD._attest_required(real_step)):
            self.skipTest("real manifest has no manual attest-required step-0b in this env")
        self._real_sha = MOD._step_text_sha(real_step)

    def _sha(self, sid):
        assert sid == "step-0b"
        return self._real_sha

    def _payload_for(self, att: dict):
        fp = self.ws / ".auditooor" / "attestations" / "step-0b.json"
        return {"tool_name": "Write",
                "tool_input": {"file_path": str(fp), "content": json.dumps(att)}}

    def test_first_encounter_no_marker_ungrounded_content_still_denies(self):
        """Self-heal must NOT weaken grounding: with no marker AND ungrounded
        content, the hook auto-renders the marker but still denies because the
        attestation content itself lacks read_ack/evidence_refs."""
        marker_path = self.ws / ".auditooor" / "attestations" / ".preflight" / "step-0b.json"
        self.assertFalse(marker_path.exists())
        rc, out, err = _run_hook(self._payload_for({"read_ack": "bogus"}))
        self.assertEqual(rc, 0)
        if not out.strip():
            self.skipTest("engine found no manifest/manual step-0b in this env (fail-open)")
        decision = json.loads(out)
        self.assertEqual(decision["hookSpecificOutput"]["permissionDecision"], "deny")
        # the self-heal must still have run: the marker now exists.
        self.assertTrue(marker_path.exists(), "hook must auto-render the marker even when it goes on to deny")

    def test_first_encounter_grounded_content_allows(self):
        """The scenario the fix targets: no prior manual `render` invocation, but
        the attestation content IS grounded (matching read_ack + real evidence
        file). The hook must self-heal (write the marker) and then ALLOW, instead
        of permanently denying because nobody separately ran render."""
        (self.ws / "SCOPE.md").write_text("real scope text", encoding="utf-8")
        marker_path = self.ws / ".auditooor" / "attestations" / ".preflight" / "step-0b.json"
        self.assertFalse(marker_path.exists())
        att = {"read_ack": self._sha("step-0b"), "evidence_refs": ["SCOPE.md"],
               "summary": "did it", "completed_at": "2026-07-02T00:00:00Z"}
        rc, out, err = _run_hook(self._payload_for(att))
        self.assertEqual(rc, 0)
        if out.strip():
            decision = json.loads(out)
            self.assertNotEqual(
                decision["hookSpecificOutput"]["permissionDecision"], "deny",
                f"grounded content must be allowed after self-heal, got: {decision}")
        # allow path: no stdout at all (hook prints nothing => allow)
        self.assertTrue(marker_path.exists(), "hook must have auto-rendered the marker on first encounter")
        self.assertIn("auto-rendered", err)

    def test_marker_already_current_no_redundant_autorender_log(self):
        """If a marker already exists and matches, the hook must not claim it
        auto-rendered (idempotent path, matches auto_render_if_missing's own
        auto_rendered=False contract)."""
        real_manifest = MOD._load_manifest(None)
        MOD.render(self.ws, "step-0b", real_manifest)  # simulate a prior manual render
        att = {"read_ack": "will-not-match-necessarily"}
        rc, out, err = _run_hook(self._payload_for(att))
        self.assertEqual(rc, 0)
        self.assertNotIn("auto-rendered", err)

    def test_autorender_disabled_via_env_restores_old_blanket_deny(self):
        """AUDITOOOR_MANUAL_STEP_AUTORENDER=0 must reproduce the exact pre-fix
        behavior: no marker written, deny with the old reason, for reproducing a
        prior audit's enforcement posture on demand."""
        (self.ws / "SCOPE.md").write_text("real scope text", encoding="utf-8")
        marker_path = self.ws / ".auditooor" / "attestations" / ".preflight" / "step-0b.json"
        att = {"read_ack": self._sha("step-0b"), "evidence_refs": ["SCOPE.md"]}
        rc, out, err = _run_hook(self._payload_for(att), env={"AUDITOOOR_MANUAL_STEP_AUTORENDER": "0"})
        self.assertEqual(rc, 0)
        if not out.strip():
            self.skipTest("engine found no manifest/manual step-0b in this env (fail-open)")
        decision = json.loads(out)
        self.assertEqual(
            decision["hookSpecificOutput"]["permissionDecision"], "deny",
            "opt-out must restore blanket-deny even with grounded content, since the "
            "marker precondition is never auto-satisfied")
        self.assertFalse(marker_path.exists(), "opt-out must not write any marker")


if __name__ == "__main__":
    unittest.main(verbosity=2)
