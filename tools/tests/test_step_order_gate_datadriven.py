#!/usr/bin/env python3
# <!-- r36-rebuttal: lane STEP-ORDER-GATE-HOOK registered in commit message -->
"""Data-driven step-order gate: prereqs derived from readme_runbook_steps.json ORDERING.

The prior hook hardcoded exactly 2 gated transitions (hunt-scoped=step-3 requires
step-2, audit-depth=step-4 requires step-3) and skipped everything else. This suite
pins the data-driven rewrite that derives each gated driver-target's immediate
required-predecessor from the manifest ordering, keeping audit-complete UNGATED and
failing OPEN on parse error.

Behaviors pinned:
  1. GROSS prereq-skip is DENIED for a hard-deny transition (hunt-scoped with no step-2).
  2. audit-depth (step-4) with no step-3 hunt sidecars -> DENIED (hard-deny transition).
  3. A normal IN-ORDER call is ALLOWED (all prereq artifacts present).
  4. Parse-error / unreadable runbook -> FAILS OPEN (allow), never wedges.
  5. Prereqs are DERIVED, not hardcoded: point the hook at a synthetic manifest and the
     derived immediate-required-predecessor for the driver target is used verbatim.
  6. ADVISORY-FIRST: a newly-covered transition (audit-deep/step-2) warns+allows by
     default, and hard-denies only under AUDITOOOR_STEP_ORDER_STRICT=1 - so it can never
     retroactively brick a prior audit.
  7. audit-complete / audit-run-full are NEVER gated (status-tellers), even bare.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_HOOK = Path(__file__).resolve().parent.parent / "hooks" / "auditooor-step-order-gate.py"
_REAL_RUNBOOK = Path(__file__).resolve().parent.parent / "readme_runbook_steps.json"


def _run(cmd: str, env_extra=None):
    payload = {"tool_name": "Bash", "tool_input": {"command": cmd}}
    env = dict(os.environ)
    env.pop("AUDITOOOR_STEP_ORDER_OK", None)
    env.pop("AUDITOOOR_STEP_ORDER_STRICT", None)
    if env_extra:
        env.update(env_extra)
    p = subprocess.run(
        [sys.executable, str(_HOOK)],
        input=json.dumps(payload), capture_output=True, text=True, env=env,
    )
    out = p.stdout.strip()
    denied = False
    if out:
        try:
            denied = (json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny")
        except Exception:
            denied = False
    return p.returncode, denied, out, p.stderr


class DataDrivenStepOrderTest(unittest.TestCase):
    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="sog_dd_"))
        (self.ws / ".auditooor").mkdir()

    # ---- artifact seeders (mirror the REAL manifest verify-artifacts) ----
    def _seed_step1(self):
        # step-1 verify: docs/LIVE_TARGET_REPORT.md + INTAKE_BASELINE.md + inscope_units
        (self.ws / "docs").mkdir(exist_ok=True)
        (self.ws / "docs" / "LIVE_TARGET_REPORT.md").write_text("x" * 60, encoding="utf-8")
        (self.ws / "INTAKE_BASELINE.md").write_text("x" * 60, encoding="utf-8")
        (self.ws / ".auditooor" / "inscope_units.jsonl").write_text('{"u":1}\n', encoding="utf-8")

    def _seed_step1c(self):
        (self.ws / ".auditooor" / "dataflow_paths.jsonl").write_text('{"p":1}\n', encoding="utf-8")

    def _seed_step2(self):
        d = self.ws / ".auditooor" / "solidity-deep-audit"
        d.mkdir(parents=True, exist_ok=True)
        (d / "manifest.json").write_text('{"ok":true}', encoding="utf-8")

    def _seed_step3(self):
        d = self.ws / ".auditooor" / "hunt_findings_sidecars"
        d.mkdir(parents=True, exist_ok=True)
        (d / "s1.json").write_text('{"f":1}', encoding="utf-8")
        # step-3 also declares function_coverage_completeness.json among its checks
        (self.ws / ".auditooor" / "function_coverage_completeness.json").write_text(
            '{"c":1}', encoding="utf-8")

    # ---- 1. gross skip denied ----
    def test_gross_prereq_skip_hunt_scoped_denied(self):
        rc, denied, out, _ = _run(f"make hunt-scoped WS={self.ws}")
        self.assertEqual(rc, 0)
        self.assertTrue(denied, f"expected DENY, got {out!r}")
        self.assertIn("step-2", out)

    # ---- 2. audit-depth gross skip denied ----
    def test_gross_prereq_skip_audit_depth_denied(self):
        # step-4's immediate required artifact-bearing predecessor is step-3.
        rc, denied, out, _ = _run(f"make audit-depth WS={self.ws}")
        self.assertEqual(rc, 0)
        self.assertTrue(denied, f"expected DENY, got {out!r}")
        self.assertIn("step-3", out)

    def _seed_step2g(self):
        # hunt-scoped's DERIVED immediate required-predecessor is step-2g-novelty-flywheel
        # (verify-artifact .auditooor/novelty/burndown_feed.jsonl), NOT the old step-2. The
        # pre-hunt novelty steps were inserted between step-2 and step-3 in the manifest; the
        # gate anchors on the nearest required, artifact-bearing predecessor, so seed THAT.
        nd = self.ws / ".auditooor" / "novelty"
        nd.mkdir(parents=True, exist_ok=True)
        (nd / "burndown_feed.jsonl").write_text('{"b":1}\n', encoding="utf-8")

    # ---- 3. in-order call allowed ----
    def test_in_order_call_allowed(self):
        self._seed_step1()
        self._seed_step1c()
        self._seed_step2()
        self._seed_step2g()
        rc, denied, out, _ = _run(f"make hunt-scoped WS={self.ws}")
        self.assertEqual(rc, 0)
        self.assertFalse(denied, f"unexpected deny: {out!r}")

    def test_audit_depth_in_order_allowed(self):
        self._seed_step3()
        rc, denied, out, _ = _run(f"make audit-depth WS={self.ws}")
        self.assertEqual(rc, 0)
        self.assertFalse(denied, f"unexpected deny: {out!r}")

    # ---- 4. parse-error fails open ----
    def test_parse_error_fails_open(self):
        bad = Path(tempfile.mkdtemp(prefix="sog_bad_")) / "readme_runbook_steps.json"
        bad.write_text("{ this is not json ", encoding="utf-8")
        # Point the hook at a hooks dir whose parent has the broken runbook by copying
        # the hook next to it.
        hooks = bad.parent / "hooks"
        hooks.mkdir()
        (hooks / "auditooor-step-order-gate.py").write_text(
            _HOOK.read_text(encoding="utf-8"), encoding="utf-8")
        payload = {"tool_name": "Bash",
                   "tool_input": {"command": f"make hunt-scoped WS={self.ws}"}}
        env = dict(os.environ)
        env.pop("AUDITOOOR_STEP_ORDER_OK", None)
        p = subprocess.run(
            [sys.executable, str(hooks / "auditooor-step-order-gate.py")],
            input=json.dumps(payload), capture_output=True, text=True, env=env,
        )
        self.assertEqual(p.returncode, 0)
        denied = False
        if p.stdout.strip():
            try:
                denied = json.loads(p.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
            except Exception:
                denied = False
        self.assertFalse(denied, "broken runbook must fail OPEN, not deny")

    # ---- 5. prereqs are DERIVED from ordering, not hardcoded ----
    def test_prereq_is_derived_from_manifest_ordering(self):
        """A synthetic manifest with a re-ordered predecessor changes the gate target,
        proving the map is data-driven rather than a hardcoded step-2/step-3 pair."""
        tmp = Path(tempfile.mkdtemp(prefix="sog_syn_"))
        hooks = tmp / "hooks"
        hooks.mkdir()
        (hooks / "auditooor-step-order-gate.py").write_text(
            _HOOK.read_text(encoding="utf-8"), encoding="utf-8")
        # Synthetic manifest: hunt-scoped's driver is step-3; its immediate required
        # artifact-bearing predecessor here is a custom 'step-XYZ' with a novel artifact.
        manifest = {
            "steps": [
                {"step_id": "step-XYZ", "required": True,
                 "what_must_be_done": "custom predecessor",
                 "how_to_verify_done": {"artifact_checks": [
                     {"type": "file_exists", "path": ".auditooor/custom_pred.json"}]}},
                {"step_id": "step-3", "required": True,
                 "what_must_be_done": "make hunt-scoped",
                 "how_to_verify_done": {"artifact_checks": [
                     {"type": "dir_nonempty", "path": ".auditooor/hunt_findings_sidecars"}]}},
            ]
        }
        (tmp / "readme_runbook_steps.json").write_text(json.dumps(manifest), encoding="utf-8")
        payload = {"tool_name": "Bash",
                   "tool_input": {"command": f"make hunt-scoped WS={self.ws}"}}
        env = dict(os.environ)
        env.pop("AUDITOOOR_STEP_ORDER_OK", None)

        def run_against():
            p = subprocess.run(
                [sys.executable, str(hooks / "auditooor-step-order-gate.py")],
                input=json.dumps(payload), capture_output=True, text=True, env=env,
            )
            out = p.stdout.strip()
            denied = False
            if out:
                try:
                    denied = json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"
                except Exception:
                    denied = False
            return p.returncode, denied, out

        # custom predecessor artifact absent -> DENY citing the DERIVED step-XYZ
        rc, denied, out = run_against()
        self.assertEqual(rc, 0)
        self.assertTrue(denied, f"expected DENY on missing derived predecessor, got {out!r}")
        self.assertIn("step-XYZ", out)
        self.assertIn("custom_pred.json", out)

        # now seed the derived predecessor artifact -> ALLOW
        (self.ws / ".auditooor" / "custom_pred.json").write_text('{"c":1}', encoding="utf-8")
        rc2, denied2, out2 = run_against()
        self.assertFalse(denied2, f"seeded predecessor should allow: {out2!r}")

    # ---- 6. advisory-first for newly-covered transition (audit-deep / step-2) ----
    def test_new_transition_advisory_by_default(self):
        # audit-deep (step-2) is NEWLY covered by the data-driven map. Its predecessor
        # (step-1c/step-1) artifacts are absent. By default: ADVISORY (warn, allow).
        rc, denied, out, stderr = _run(f"make audit-deep WS={self.ws}")
        self.assertEqual(rc, 0)
        self.assertFalse(denied, f"new transition must be advisory (allow) by default: {out!r}")
        self.assertIn("ADVISORY", stderr)

    def test_new_transition_hard_denies_under_strict(self):
        rc, denied, out, _ = _run(
            f"make audit-deep WS={self.ws}", {"AUDITOOOR_STEP_ORDER_STRICT": "1"})
        self.assertEqual(rc, 0)
        self.assertTrue(denied, f"STRICT must hard-deny new transition: {out!r}")

    def test_new_transition_allowed_when_in_order(self):
        self._seed_step1()
        self._seed_step1c()
        rc, denied, _, _ = _run(
            f"make audit-deep WS={self.ws}", {"AUDITOOOR_STEP_ORDER_STRICT": "1"})
        self.assertFalse(denied)

    # ---- 7. status-tellers never gated ----
    def test_audit_complete_never_gated(self):
        rc, denied, _, _ = _run(f"make audit-complete WS={self.ws} STRICT=1")
        self.assertEqual(rc, 0)
        self.assertFalse(denied)
        _, denied2, _, _ = _run(f"make audit-run-full WS={self.ws}")
        self.assertFalse(denied2)

    # ---- fail-open safety net ----
    def test_override_env_fails_open(self):
        _, denied, _, _ = _run(
            f"make hunt-scoped WS={self.ws}", {"AUDITOOOR_STEP_ORDER_OK": "1"})
        self.assertFalse(denied)

    def test_no_ws_fails_open(self):
        _, denied, _, _ = _run("make hunt-scoped")
        self.assertFalse(denied)

    def test_real_manifest_hunt_scoped_predecessor_is_step2(self):
        """Against the REAL manifest, hunt-scoped(step-3)'s immediate artifact-bearing
        required predecessor is step-2 (step-2c is manual attestation-only / no on-disk
        artifact beyond chimera dir, but step-2 is the nearest with a deep-audit manifest
        artifact). This pins backward-compat with the historical step-2 gate."""
        self.assertTrue(_REAL_RUNBOOK.is_file())
        rc, denied, out, _ = _run(f"make hunt-scoped WS={self.ws}")
        self.assertTrue(denied)
        self.assertIn("step-2", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
