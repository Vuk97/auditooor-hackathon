#!/usr/bin/env python3
"""R82 restart-based-permanence-must-be-EXECUTED gate.

A CRITICAL permanent-freeze claim whose permanence hinges on a restart /
state-resident leg ("a plain restart re-loads the flood and re-fails") must
DEMONSTRATE that leg with an executed close-and-reopen restart-survival PoC
(round11 discipline), not source-traced prose. Source-only prose is exactly
the Permanent(Critical)-vs-Temporary(High) hinge and cannot be asserted.

Stdlib-only, hermetic. Module loaded via importlib (hyphenated filename).
"""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "impact-recovery-falsification-check.py"


def _load():
    spec = importlib.util.spec_from_file_location("r82_restart_mod", TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["r82_restart_mod"] = m
    spec.loader.exec_module(m)
    return m


MOD = _load()

_RESTART_CRITICAL_BODY = """# Permanent freezing of funds via consensus halt

Permanent freezing of funds: a permissionless flood stalls BeginBlocker.

## Victim Recovery Enumeration

impact-lands: src/vault/keeper/abci.go:18 (the due-set is committed here)

| Recovery path | verdict |
| --- | --- |
| Node restart (no patch) at src/vault/queue/payout_timeout.go:58 | FAILS - a plain restart re-loads the store-resident flood and re-stalls |

verdict: no-in-protocol-recovery-exists

The only recovery is a coordinated out-of-protocol hardfork.
"""


def _run(body, poc_dir=None, override="CRITICAL"):
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8") as tf:
        tf.write(body)
        p = Path(tf.name)
    try:
        return MOD.check(p, None, poc_dir, override, False)
    finally:
        p.unlink(missing_ok=True)


class TestRestartExecutedGate(unittest.TestCase):
    def test_prose_only_critical_restart_claim_FAILS(self):
        out = _run(_RESTART_CRITICAL_BODY)
        self.assertEqual(out["verdict"], "fail-restart-permanence-not-executed",
                         f"prose-only restart permanence should FAIL, got {out['verdict']}")

    def test_structural_close_and_reopen_prose_does_NOT_satisfy(self):
        # The exact NUVA prose that slipped through before.
        body = _RESTART_CRITICAL_BODY + "\nThe close-and-reopen behavior is structural (state-resident queue).\n"
        out = _run(body)
        self.assertEqual(out["verdict"], "fail-restart-permanence-not-executed")

    def test_executed_transcript_in_pocdir_PASSES_the_gate(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "abci-poc_permanence_transcript.txt").write_text(
                "=== RUN   TestRestartSurvival\n"
                "RESTART SURVIVAL CONFIRMED: reopened app re-stalled on the persisted flood\n"
                "--- PASS: TestRestartSurvival (0.09s)\n", encoding="utf-8")
            out = _run(_RESTART_CRITICAL_BODY, poc_dir=Path(d))
        self.assertNotEqual(out["verdict"], "fail-restart-permanence-not-executed")

    def test_dedicated_rebuttal_bypasses(self):
        body = _RESTART_CRITICAL_BODY + \
            "\n<!-- r82-restart-executed-rebuttal: permanence is via a burned admin key, not a restart leg -->\n"
        out = _run(body)
        self.assertNotEqual(out["verdict"], "fail-restart-permanence-not-executed")

    def test_generic_r82_rebuttal_does_NOT_buy_it_out(self):
        body = _RESTART_CRITICAL_BODY + "\n<!-- r82-rebuttal: recovery falsified in the table above -->\n"
        out = _run(body)
        self.assertEqual(out["verdict"], "fail-restart-permanence-not-executed",
                         "a generic prose r82-rebuttal must NOT satisfy the executed-restart requirement")

    def test_CONTROL_non_restart_permanence_not_required(self):
        # Permanence via a burned key / no-reset-path - no restart leg -> gate does not fire.
        body = """# Permanent freezing via a one-way verifier-nullified flag

Permanent freezing of funds: a single caller nullifies the verifier with no reset path.

## Victim Recovery Enumeration

impact-lands: src/Game.sol:210 (the nullified flag is committed here)

| Recovery path | verdict |
| --- | --- |
| resetVerifier() at src/Game.sol:88 | excluded: function does not exist (no reset path) |

verdict: no-in-protocol-recovery-exists
"""
        out = _run(body)
        self.assertNotEqual(out["verdict"], "fail-restart-permanence-not-executed",
                            "non-restart permanence must not trip the restart-executed gate")

    def test_CONTROL_high_tier_restart_not_required(self):
        # High (temporary) claim with a restart mention -> below Critical -> gate does not fire.
        out = _run(_RESTART_CRITICAL_BODY, override="HIGH")
        self.assertNotEqual(out["verdict"], "fail-restart-permanence-not-executed")


if __name__ == "__main__":
    unittest.main()
