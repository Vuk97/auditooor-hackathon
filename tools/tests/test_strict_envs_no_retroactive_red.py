#!/usr/bin/env python3
"""test_strict_envs_no_retroactive_red.py

GRADUATION-SAFETY guard for the enforcement-wiring loop (2026-07-03): every
advisory-first done-guard STRICT env added by the loop is default-OFF and must
NEVER retroactively red a PARKED audit (the operator's hard rule). This pins the
property mechanically: turning ALL six done-guard strict envs ON at once must
produce the EXACT SAME fail_gates as default on each sample workspace present on
the host - i.e. graduation is a verified no-op for a real parked audit; the strict
envs only bite on their specific trip conditions (forged marker, degraded closure,
failing native suite, stale pin, shallow dispositions, missing prior-audits), none
of which a parked audit that is already red on real coverage gates exhibits.

Host-conditional: skips a sample ws that is not present (like
test_marker_tamper_evidence.TestFlagUnsetRegressionBaseline).
"""
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

_GUARD = Path(__file__).resolve().parents[1] / "audit-done-guard.py"

_STRICT_ENVS = {
    "AUDITOOOR_DONE_DISPOSITION_STRICT": "1",
    "AUDITOOOR_DONE_PRIOR_AUDIT_STRICT": "1",
    "AUDITOOOR_DONE_STALE_PIN_STRICT": "1",
    "AUDITOOOR_DONE_CLOSURE_DEGRADE_STRICT": "1",
    "AUDITOOOR_DONE_NATIVE_SUITE_STRICT": "1",
    "AUDITOOOR_MARKER_TAMPER_STRICT": "1",
}

_SAMPLES = [f"/Users/wolf/audits/{n}" for n in ("strata", "near-intents", "etherfi", "polygon", "nuva")]


def _run(ws: str, env_extra: dict) -> dict:
    env = {k: v for k, v in os.environ.items() if k not in _STRICT_ENVS}
    env.update(env_extra)
    r = subprocess.run([sys.executable, str(_GUARD), ws, "--json"],
                       capture_output=True, text=True, env=env, timeout=180)
    try:
        return json.loads(r.stdout or "{}")
    except ValueError:
        return {}


class TestStrictEnvsNoRetroactiveRed(unittest.TestCase):
    def test_default_matches_explicit_off(self):
        # The default-ON graduation (2026-07-03) was REVERTED the same day: NUVA was the
        # first audit to actually REACH these FINAL-BOUNDARY sub-gates (all other L37 gates
        # pass) and exposed that they systematically false-positive there - marker-tamper's
        # enforcer-hash is unstable across a make run, and disposition-distinctness mis-scopes
        # mechanism-impossibility refutations as shallow dedup-kills. The parked-audit
        # graduation test missed this because parked audits fail EARLIER and never reach the
        # blocks. So these envs are default-OFF (advisory) again. This pins the post-revert
        # invariant: the DEFAULT (env unset) verdict EQUALS the explicit-OFF verdict - i.e.
        # absence of the env cannot enforce (advisory-first), so no audit is retroactively red-ed.
        optout = {k: "0" for k in _STRICT_ENVS}
        ran = 0
        for ws in _SAMPLES:
            if not Path(ws).is_dir():
                continue
            ran += 1
            default = _run(ws, {})       # env unset -> must behave as advisory (off)
            off = _run(ws, optout)       # explicit opt-out
            self.assertTrue(default, f"{ws}: done-guard produced no JSON (crash?)")
            self.assertEqual(default.get("done"), off.get("done"),
                             f"{ws}: default (unset) differs from explicit-off - an env "
                             "enforces by default (not advisory-first)")
            self.assertEqual(sorted(default.get("fail_gates", [])),
                             sorted(off.get("fail_gates", [])),
                             f"{ws}: default (unset) fail_gates differ from explicit-off - "
                             "a done-guard sub-gate is enforcing by default")
        if not ran:
            self.skipTest("no sample workspaces present on this host")


if __name__ == "__main__":
    unittest.main()
