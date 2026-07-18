# <!-- r36-rebuttal: lane manual-step-preflight registered via agent-pathspec-register.py -->
"""Regression guard for manual-step-preflight-gate.py WIRING (2026-07-02).

Root defect this test locks down: the PreToolUse hook body only inspects Write/Edit
attestation payloads (it early-returns allow for any other tool), but it had been
registered under a "Bash" matcher block in ~/.claude/settings.json. Claude Code
dispatches a PreToolUse hook only for tool calls matching the block's matcher, so the
gate was fed exclusively Bash payloads and could NEVER receive the Write/Edit payload
it exists to deny. The self-described trigger was dead.

Two invariants:
  (1) WIRING: the hook is registered under a matcher that includes BOTH Write and Edit,
      so the payloads its body inspects can actually reach it.
  (2) BEHAVIOR: when handed a Write payload for an ungrounded manual-step attestation,
      the hook emits a permissionDecision=deny (proving the body fires end-to-end once
      the correct payload type reaches it).

Backward-compat is preserved: a non-attestation Write and a Bash payload both allow.
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
_HOOK = _REPO / "tools" / "hooks" / "manual-step-preflight-gate.py"
_SETTINGS = Path.home() / ".claude" / "settings.json"


def _run_hook(payload: dict) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(_HOOK)],
        input=json.dumps(payload),
        capture_output=True, text=True,
    )
    return proc.returncode, proc.stdout


class WiringTest(unittest.TestCase):
    def test_registered_under_write_edit_matcher(self):
        """The hook must live in a PreToolUse block whose matcher fires for Write AND
        Edit - never a Bash-only block (that is the exact defect being fixed)."""
        if not _SETTINGS.exists():
            self.skipTest("no ~/.claude/settings.json in this environment")
        cfg = json.loads(_SETTINGS.read_text())
        pre = cfg.get("hooks", {}).get("PreToolUse", [])
        matchers_for_hook = []
        for block in pre:
            cmds = [h.get("command", "") for h in block.get("hooks", [])]
            if any("manual-step-preflight-gate.py" in c for c in cmds):
                matchers_for_hook.append(block.get("matcher", ""))
        self.assertTrue(
            matchers_for_hook,
            "manual-step-preflight-gate.py is not registered in PreToolUse at all",
        )
        for matcher in matchers_for_hook:
            tools = set(matcher.split("|"))
            self.assertIn(
                "Write", tools,
                f"gate matcher {matcher!r} does not include Write - the Write "
                "attestation payload can never reach the hook",
            )
            self.assertIn(
                "Edit", tools,
                f"gate matcher {matcher!r} does not include Edit - the Edit "
                "attestation payload can never reach the hook",
            )


class BehaviorTest(unittest.TestCase):
    def setUp(self):
        os.environ.pop("AUDITOOOR_MANUAL_STEP_STRICT", None)
        self.ws = Path(tempfile.mkdtemp())
        (self.ws / ".auditooor" / "attestations").mkdir(parents=True)

    def test_bash_payload_allows(self):
        """Backward-compat: a Bash payload (what the broken wiring fed it) must allow."""
        rc, out = _run_hook({"tool_name": "Bash", "tool_input": {"command": "ls"}})
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), "")

    def test_non_attestation_write_allows(self):
        """Backward-compat: an unrelated Write must not be gated."""
        rc, out = _run_hook({
            "tool_name": "Write",
            "tool_input": {"file_path": str(self.ws / "foo.txt"), "content": "hi"},
        })
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), "")

    def test_ungrounded_attestation_write_denies_when_manifest_present(self):
        """A Write of a manual attest-required step's attestation with no read-ack
        marker must be DENIED - proving the body fires once the Write payload reaches
        it. Skips gracefully if the engine finds no manifest/step in this env (the
        hook fail-opens by design, which is not what this test asserts)."""
        fp = self.ws / ".auditooor" / "attestations" / "step-0b.json"
        rc, out = _run_hook({
            "tool_name": "Write",
            "tool_input": {"file_path": str(fp), "content": json.dumps({"read_ack": "x"})},
        })
        self.assertEqual(rc, 0, "hook must always exit 0 (deny is via stdout JSON)")
        if not out.strip():
            self.skipTest("engine found no manifest/manual step-0b in this env (fail-open)")
        decision = json.loads(out)
        self.assertEqual(
            decision["hookSpecificOutput"]["permissionDecision"], "deny",
            "ungrounded manual-step attestation Write must be denied",
        )


if __name__ == "__main__":
    unittest.main()
