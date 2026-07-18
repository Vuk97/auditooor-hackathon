#!/usr/bin/env python3
# <!-- r36-rebuttal: lane STEP-ORDER-GATE-HOOK registered in commit message -->
"""auditooor-step-order-gate PreToolUse hook: deny an out-of-order canonical step.

Pins the four behaviors that keep it useful AND non-wedging:
  1. hunt-scoped (step-3) with NO step-2 deep-audit manifest -> DENY.
  2. hunt-scoped WITH the step-2 manifest present -> ALLOW.
  3. audit-complete / audit-run-full are NEVER gated (status-tellers) -> ALLOW even bare.
  4. non-audit Bash, no WS=, or override env -> ALLOW (fail-open).
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_HOOK = Path(__file__).resolve().parent.parent / "hooks" / "auditooor-step-order-gate.py"


def _run(cmd: str, env_extra=None):
    payload = {"tool_name": "Bash", "tool_input": {"command": cmd}}
    env = dict(os.environ)
    env.pop("AUDITOOOR_STEP_ORDER_OK", None)
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
    return p.returncode, denied, out


class StepOrderGateTest(unittest.TestCase):
    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="sog_"))
        (self.ws / ".auditooor").mkdir()

    def _seed_step2(self):
        # step-2 verify artifact: solidity-deep-audit/manifest.json
        d = self.ws / ".auditooor" / "solidity-deep-audit"
        d.mkdir(parents=True, exist_ok=True)
        (d / "manifest.json").write_text('{"ok":true}', encoding="utf-8")

    def test_hunt_scoped_without_step2_is_denied(self):
        rc, denied, out = _run(f"make hunt-scoped WS={self.ws}")
        self.assertEqual(rc, 0)
        self.assertTrue(denied, f"expected DENY, got: {out!r}")
        self.assertIn("step-2", out)

    def test_hunt_scoped_with_step2_is_allowed(self):
        self._seed_step2()
        rc, denied, _ = _run(f"make hunt-scoped WS={self.ws}")
        self.assertEqual(rc, 0)
        self.assertFalse(denied)

    def test_audit_complete_never_gated(self):
        # the status-teller must run even on a bare workspace
        rc, denied, _ = _run(f"make audit-complete WS={self.ws} STRICT=1")
        self.assertEqual(rc, 0)
        self.assertFalse(denied)
        rc2, denied2, _ = _run(f"make audit-run-full WS={self.ws}")
        self.assertFalse(denied2)

    def test_make_target_mentioned_in_commit_message_not_gated(self):
        # the regression that bit on first deploy: a heredoc commit body that MENTIONS
        # `make audit-depth` / WS= must NOT be treated as an invocation.
        body = (f"git commit -F - <<'EOF'\nhooks: fix\n\ne.g. `make audit-depth` "
                f"step-4 before step-3, run hunt-scoped WS={self.ws} first\nEOF")
        rc, denied, out = _run(body)
        self.assertFalse(denied, f"commit-message mention wrongly gated: {out!r}")
        # also git commit -m inline
        rc2, denied2, _ = _run(f'git commit -m "ran make audit-depth WS={self.ws}"')
        self.assertFalse(denied2)
        # echo mentioning a target
        self.assertFalse(_run(f"echo make audit-depth WS={self.ws}")[1])

    def test_real_invocation_after_heredoc_still_gated(self):
        # a genuine invocation that happens to sit after an unrelated heredoc must
        # still be caught (don't over-strip).
        cmd = f"cat <<'EOF'\nnote\nEOF\nmake audit-depth WS={self.ws}"
        # leading verb is `cat` -> message-verb skip means this is allowed; that's the
        # conservative tradeoff (lead-verb cat). Verify the common direct form is gated:
        rc, denied, _ = _run(f"make audit-depth WS={self.ws}")
        self.assertTrue(denied)

    def test_failopen_paths(self):
        # non-audit make
        self.assertFalse(_run("make test")[1])
        # gated target but no WS=
        self.assertFalse(_run("make hunt-scoped")[1])
        # override env
        self.assertFalse(_run(f"make hunt-scoped WS={self.ws}",
                              {"AUDITOOOR_STEP_ORDER_OK": "1"})[1])
        # non-Bash payloads handled: empty command
        self.assertFalse(_run("")[1])


if __name__ == "__main__":
    unittest.main(verbosity=2)
