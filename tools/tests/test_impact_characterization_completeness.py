#!/usr/bin/env python3
"""Tests for tools/impact-characterization-completeness-check.py.

Covers:
  (i)   TRUE-POSITIVE: a freezing-Critical draft missing the recovery ladder /
        claiming a tier above its evidence class -> flagged (rc=1 under STRICT).
  (ii)  FP-SUPPRESSION: a fully-characterized High freezing draft with all axes
        answered -> passes (rc=0 even under STRICT).
  (iii) SOURCE-ONLY / REBUTTAL: a source-only draft satisfies net-new axes via
        source-cited N/A + a rebuttal marker -> not hard-failed.
  (iv)  ADVISORY-vs-STRICT rc parity: identical verdict, rc=0 without env / rc=1 with.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
TOOL = TOOLS / "impact-characterization-completeness-check.py"


def _run(draft: str, *, strict: bool = False, env_strict: bool = False) -> tuple[int, dict]:
    with_tmp = Path(os.environ.get("TMPDIR", "/tmp")) / f"_icc_{abs(hash(draft)) % 10**8}.md"
    with_tmp.write_text(draft, encoding="utf-8")
    env = dict(os.environ)
    env.pop("AUDITOOOR_IMPACT_CHARACTERIZATION_STRICT", None)
    if env_strict:
        env["AUDITOOOR_IMPACT_CHARACTERIZATION_STRICT"] = "1"
    cmd = [sys.executable, str(TOOL), str(with_tmp), "--json"]
    if strict:
        cmd.append("--strict")
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=180)
    try:
        payload = json.loads(proc.stdout)
    except Exception:
        payload = {"_stdout": proc.stdout, "_stderr": proc.stderr}
    return proc.returncode, payload


# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------
# (i) Critical freeze, NO recovery section, bare axes, in-process-only PoC.
TP_FREEZE_CRITICAL_INCOMPLETE = """# Permanent freeze of user funds

Severity: Critical

User funds are permanently frozen in the vault forever; the withdrawal path for
user funds is bricked and user funds can never be recovered.

## Impact Characterization

IMPACT_CLASS: permanent-freeze-funds
- RECOVERY_LADDER: TBD
- EVIDENCE_CLASS_BOUNDARY: TBD
- SELF_IMPACT: TBD
"""

# (ii) Fully-characterized HIGH temporary freeze with all axes answered + recovery section.
FP_FREEZE_HIGH_COMPLETE = """# Temporary freeze of user funds

Severity: High

User funds are temporarily frozen: the withdrawal queue for user funds stalls for
a bounded window and then drains, temporarily freezing user funds.

## Victim Recovery Enumeration

The impact lands at src/Vault.sol:412 where the queue head is committed. Recovery:
the permissionless `pokeQueue()` at src/Vault.sol:455 drains the queue next epoch.

| entrypoint | file:line | outcome |
| pokeQueue | src/Vault.sol:455 | drains queue, releases funds next epoch |

## Impact Characterization

IMPACT_CLASS: temporary-freeze-funds
- RECOVERY_LADDER: reachable permissionless recovery via pokeQueue [source-cited src/Vault.sol:455]
- DURATION_QUANTIFIED: 1 epoch = 6 hours, measured in the forge PoC [measured]
- SELF_THROTTLE: no economic self-throttle, attacker pays gas each block [source-cited src/Vault.sol:455]
- EVIDENCE_CLASS_BOUNDARY: contract-local queue only, no wider claim [source-cited src/Vault.sol:412]
- SELF_IMPACT: victim depositors' balances frozen, not attacker's [source-cited src/Vault.sol:412]
"""

# (iii) Source-only temporary freeze: net-new axes answered via source-cited N/A + rebuttal.
SOURCE_ONLY_REBUTTAL = """# Temporary freeze of user funds (source-only)

Severity: High

Scope mode: source-only

User funds are temporarily frozen when the queue for user funds stalls; funds are
released once the epoch advances.

## Victim Recovery Enumeration

The impact lands at src/Vault.sol:412. Recovery via epoch advance at src/Vault.sol:455.

| entrypoint | file:line | outcome |
| epochTick | src/Vault.sol:455 | advances epoch, releases funds |

## Impact Characterization

IMPACT_CLASS: temporary-freeze-funds
- RECOVERY_LADDER: source-traced recovery via epochTick [source-cited src/Vault.sol:455]
- DURATION_QUANTIFIED: N/A: source-only scope, duration not executable, bounded by epoch [source-cited src/Vault.sol:455]
- SELF_THROTTLE: N/A: no economic feedback in source path [source-cited src/Vault.sol:412]
- EVIDENCE_CLASS_BOUNDARY: contract-local only [source-cited src/Vault.sol:412]
- SELF_IMPACT: victim depositors [source-cited src/Vault.sol:412]

<!-- impact-characterization-rebuttal: source-only draft; net-new axes N/A per source trace, mirrors R82 pass-claim-narrowed -->
"""


# (v) NUVA reproduction: a griefing/DoS Critical that mis-applies a panic transcript
#     as a chain-halt claim, with no PoC dir -> flagged on the panic + tier axes.
NUVA_GRIEFING_PANIC_HALT = """# Chain halt via unbounded queue (griefing / DoS)

Severity: Critical

An attacker floods the mempool and triggers a chain halt / liveness failure: the
validator halts block production. Transcript:

    panic: runtime error: index out of range
    goroutine 42 [running]

This is a griefing denial-of-service that halts the chain.

## Impact Characterization

IMPACT_CLASS: griefing-dos
- PANIC_VS_SLOWNESS: crash (panic) [source-cited x/app/handler.go:88]
"""


class ImpactCharacterizationCompletenessTest(unittest.TestCase):
    def test_i_true_positive_freeze_critical_incomplete_flagged(self):
        # Advisory (no strict): verdict is fail, rc stays 0.
        rc, payload = _run(TP_FREEZE_CRITICAL_INCOMPLETE, strict=False)
        self.assertEqual(payload["impact_id"], "permanent-freeze-funds")
        self.assertTrue(payload["verdict"].startswith("fail"), payload["verdict"])
        self.assertEqual(rc, 0, "advisory-first: rc must be 0 without strict")
        # A recovery-ladder or bare-axis failure must be present.
        joined = " ".join(payload["failures"])
        self.assertIn("RECOVERY_LADDER", joined)
        # Under strict, the same incomplete draft fails closed.
        rc_s, payload_s = _run(TP_FREEZE_CRITICAL_INCOMPLETE, strict=True)
        self.assertTrue(payload_s["verdict"].startswith("fail"))
        self.assertEqual(rc_s, 1, "strict: incomplete freeze must rc=1")

    def test_ii_fp_suppression_high_freeze_complete_passes(self):
        rc, payload = _run(FP_FREEZE_HIGH_COMPLETE, strict=True)
        self.assertEqual(payload["impact_id"], "temporary-freeze-funds")
        self.assertTrue(
            payload["verdict"].startswith("pass"),
            f"complete High freeze should pass; got {payload['verdict']} / {payload['failures']}",
        )
        self.assertEqual(rc, 0)

    def test_iii_source_only_rebuttal_not_hard_failed(self):
        rc, payload = _run(SOURCE_ONLY_REBUTTAL, strict=True)
        self.assertTrue(
            payload["verdict"].startswith("pass"),
            f"source-only + N/A + rebuttal should not hard-fail; got "
            f"{payload['verdict']} / {payload['failures']}",
        )
        self.assertEqual(rc, 0)

    def test_iv_advisory_vs_strict_rc_parity(self):
        # Same draft, same verdict; rc differs only by env.
        rc_adv, p_adv = _run(TP_FREEZE_CRITICAL_INCOMPLETE, env_strict=False)
        rc_env, p_env = _run(TP_FREEZE_CRITICAL_INCOMPLETE, env_strict=True)
        self.assertEqual(p_adv["verdict"], p_env["verdict"], "identical verdict")
        self.assertEqual(rc_adv, 0)
        self.assertEqual(rc_env, 1, "env AUDITOOOR_IMPACT_CHARACTERIZATION_STRICT enforces")

    def test_v_nuva_griefing_panic_halt_flagged(self):
        rc, payload = _run(NUVA_GRIEFING_PANIC_HALT, strict=True)
        self.assertEqual(payload["impact_id"], "griefing-dos")
        self.assertTrue(payload["verdict"].startswith("fail"), payload["verdict"])
        self.assertEqual(rc, 1)
        joined = " ".join(payload["failures"])
        # The panic-vs-slowness axis (delegated to panic-context-audit.py) must flag,
        # and/or the missing net-new axes (DRAIN_VS_REENQUEUE, DURATION) must be bare.
        self.assertTrue(
            "PANIC_VS_SLOWNESS" in joined
            or "DRAIN_VS_REENQUEUE" in joined
            or "TIER_VS_EVIDENCE" in joined,
            joined,
        )

    def test_no_em_dashes_in_output(self):
        rc, payload = _run(FP_FREEZE_HIGH_COMPLETE)
        blob = json.dumps(payload)
        self.assertNotIn("—", blob)
        self.assertNotIn("–", blob)


if __name__ == "__main__":
    unittest.main()
