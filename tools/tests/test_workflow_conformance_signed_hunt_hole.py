#!/usr/bin/env python3
# <!-- r36-rebuttal: lane WORKFLOW-CONFORMANCE-SIGNED-HUNT-HOLE registered in commit message -->
"""workflow-dispatch-conformance: a DISPATCH-INTENT sign must NOT launder a BESPOKE HUNT.

Strata 2026-06-30: a hunt-shaped Workflow that returned leads to the orchestrator (no
verdict-sink / hunt_findings_sidecars routing) sailed through because it carried
`DISPATCH-INTENT: capability` - the signed bypass fired BEFORE the bespoke-hunt check.
Pin: signed bespoke-hunt -> DENY; signed canonical-hunt / non-hunt -> allow; env override
-> allow.
"""
import json, os, subprocess, sys, tempfile, unittest
from pathlib import Path

_HOOK = Path(__file__).resolve().parent.parent / "hooks" / "workflow-dispatch-conformance.py"


def _run(script, env_extra=None):
    ws = tempfile.mkdtemp()
    payload = {"tool_name": "Workflow", "tool_input": {"script": script},
               "cwd": f"/Users/wolf/audits/strata"}
    env = dict(os.environ); env.pop("AUDITOOOR_BESPOKE_DISPATCH_OK", None)
    if env_extra:
        env.update(env_extra)
    p = subprocess.run([sys.executable, str(_HOOK)], input=json.dumps(payload),
                       capture_output=True, text=True, env=env)
    denied = False
    if p.stdout.strip():
        try:
            denied = json.loads(p.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
        except Exception:
            denied = False
    return denied


# hunt-shaped tokens the hook keys on: finding/severity/exploit/hunt/...
_BESPOKE_HUNT = """export const meta = { name: 'strata-hunt', description: 'fan out finding hunt' }
// audit /audits/strata - agents emit severity findings, return leads to orchestrator
agent('hunt for vuln/exploit findings, return severity leads')"""
_CANONICAL_HUNT = _BESPOKE_HUNT + "\n// writes hunt_findings_sidecars via verdict-sink, make mimo-corpus-mine"
_SIGNED = "// DISPATCH-INTENT: capability\n"


class SignedHuntHoleTest(unittest.TestCase):
    def test_signed_bespoke_hunt_is_DENIED(self):
        # THE hole: signing a bespoke hunt as capability must NOT bypass.
        self.assertTrue(_run(_SIGNED + _BESPOKE_HUNT),
                        "a DISPATCH-INTENT-signed BESPOKE hunt must still be DENIED")

    def test_unsigned_bespoke_hunt_denied(self):
        self.assertTrue(_run(_BESPOKE_HUNT))

    def test_signed_canonical_hunt_allowed(self):
        # routes canonically (hunt_findings_sidecars/verdict-sink) -> allowed even though hunt-shaped
        self.assertFalse(_run(_SIGNED + _CANONICAL_HUNT))

    def test_canonical_hunt_allowed_even_unsigned(self):
        self.assertFalse(_run(_CANONICAL_HUNT))

    def test_env_override_allows_bespoke(self):
        self.assertFalse(_run(_BESPOKE_HUNT, {"AUDITOOOR_BESPOKE_DISPATCH_OK": "1"}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
