#!/usr/bin/env python3
"""capv3 iter-1 T1 — regression tests for the task-spec manifests emitted by
the end-to-end fuzz run against 11 centrifuge-v3 green harnesses.

The manifests live under
    ~/audits/centrifuge-v3/fuzz_runs/<ts>/<basename>/manifest.json
and follow a 9-field task-spec schema that is DIFFERENT from the
`tools/fuzz-runner.sh` internal schema (which is schema_version=1,
workspace/engine/timeout_seconds/...).

Pin to the batch-run timestamp produced by the T1 agent so the tests are
reproducible offline. If the workspace is unreachable (no ~/audits) the
tests skip with a clear reason — they never fabricate a pass.
"""
from __future__ import annotations

import json
import os
import unittest
from pathlib import Path


CAPV3_ITER1_TS = os.environ.get("CAPV3_ITER1_TS", "20260424T080145Z")
WORKSPACE = Path(os.environ.get("CAPV3_ITER1_WORKSPACE",
                                str(Path.home() / "audits" / "centrifuge-v3")))
RUNS_ROOT = WORKSPACE / "fuzz_runs" / CAPV3_ITER1_TS

REQUIRED_FIELDS = (
    "engine",
    "harness",
    "status",
    "reason",
    "runtime_s",
    "counterexample_trace",
    "advisory",
    "severity_upgrade_allowed",
    "evidence_matrix_contributes",
    "timestamp",
)

# Vocab lock — task truth-audit §2
ALLOWED_STATUSES = {"pass", "counterexample", "timeout", "error", "skipped"}

EXPECTED_HARNESSES = {
    "bridge_MessageProcessor_FinalityBeforeWithdraw",
    "bridge_MessageProcessor_LockMintBalanceConservation",
    "bridge_MessageProcessor_MessageReplayResistance",
    "governance_MultiAdapter_ProposalIdMonotonicity",
    "governance_MultiAdapter_QuorumEnforced",
    "governance_MultiAdapter_TimelockRespected",
    "lending_Accounting_DebtCollateralSolvency",
    "lending_Accounting_LiquidationIncentive",
    "lending_Accounting_OraclePriceDelta",
    "vault_Holdings_SharePriceMonotonicity",
    "vault_Holdings_TotalAssetsMonotonicity",
}


def _load_manifests():
    """Yield (basename, dict) pairs for each per-harness manifest.

    Skips the `_runner_exercise` sibling (it uses the fuzz-runner internal
    schema, not the task-spec schema — see FUZZ_RUN_CAPV3_ITER1.md §Invocation).
    """
    if not RUNS_ROOT.exists():
        return []
    out = []
    for child in sorted(RUNS_ROOT.iterdir()):
        if not child.is_dir():
            continue
        if child.name.startswith("_"):
            continue
        mf = child / "manifest.json"
        if not mf.exists():
            continue
        with mf.open() as fh:
            out.append((child.name, json.load(fh)))
    return out


class ManifestSchemaTest(unittest.TestCase):
    def setUp(self):
        if not RUNS_ROOT.exists():
            self.skipTest(
                f"capv3 fuzz-run root {RUNS_ROOT} is absent — this test "
                f"expects the T1 batch run (CAPV3_ITER1_TS={CAPV3_ITER1_TS}). "
                "No synthesis; skip rather than fabricate a pass."
            )
        manifests = _load_manifests()
        if not manifests:
            self.skipTest(f"no manifests under {RUNS_ROOT}")
        self.manifests = manifests

    def test_manifest_schema_required_fields(self):
        """Every per-harness manifest has all 10 task-spec fields populated.

        (The task spec enumerates 9 fields; `timestamp` is the 10th — see
        FUZZ_RUN_CAPV3_ITER1.md.)
        """
        self.assertGreaterEqual(
            len(self.manifests), 10,
            f"expected >= 10 per-harness manifests, got {len(self.manifests)}",
        )
        covered_basenames = set()
        for name, m in self.manifests:
            covered_basenames.add(name)
            for field in REQUIRED_FIELDS:
                self.assertIn(
                    field, m,
                    f"manifest {name} missing required field '{field}'",
                )
            # Status must be from the locked vocab.
            self.assertIn(
                m["status"], ALLOWED_STATUSES,
                f"manifest {name} status '{m['status']}' outside vocab "
                f"{sorted(ALLOWED_STATUSES)}",
            )
            # engine must be literal 'foundry' for T1 (the task-spec runner
            # mode). If this ever broadens, update both the task and this test.
            self.assertEqual(
                m["engine"], "foundry",
                f"manifest {name} engine '{m['engine']}' != 'foundry'",
            )
            # runtime_s is a non-negative number.
            self.assertIsInstance(
                m["runtime_s"], (int, float),
                f"manifest {name} runtime_s is not numeric",
            )
            self.assertGreaterEqual(
                m["runtime_s"], 0,
                f"manifest {name} runtime_s is negative",
            )
            # counterexample_trace must be null or a string path.
            ce = m["counterexample_trace"]
            self.assertTrue(
                ce is None or isinstance(ce, str),
                f"manifest {name} counterexample_trace is not null-or-string",
            )
            # timestamp is a non-empty ISO-ish string.
            self.assertIsInstance(
                m["timestamp"], str,
                f"manifest {name} timestamp is not a string",
            )
            self.assertTrue(
                m["timestamp"],
                f"manifest {name} timestamp is empty",
            )
        # Expected harness set must be fully covered.
        missing = EXPECTED_HARNESSES - covered_basenames
        self.assertFalse(
            missing,
            f"manifests missing for harnesses: {sorted(missing)}",
        )


class AdvisoryFlagsTest(unittest.TestCase):
    def setUp(self):
        if not RUNS_ROOT.exists():
            self.skipTest(
                f"capv3 fuzz-run root {RUNS_ROOT} is absent — expected T1 "
                f"batch under CAPV3_ITER1_TS={CAPV3_ITER1_TS}."
            )
        self.manifests = _load_manifests()
        if not self.manifests:
            self.skipTest(f"no manifests under {RUNS_ROOT}")

    def test_advisory_flags_preserved(self):
        """Hard negative: every manifest must be advisory-only, ineligible
        for severity upgrade, and excluded from the evidence matrix.

        This mirrors the task's `Hard negative: no manifest has
        evidence_matrix_contributes: true` acceptance criterion.
        """
        for name, m in self.manifests:
            self.assertIs(
                m.get("advisory"), True,
                f"manifest {name}: advisory must be true (got {m.get('advisory')!r})",
            )
            self.assertIs(
                m.get("severity_upgrade_allowed"), False,
                f"manifest {name}: severity_upgrade_allowed must be false "
                f"(got {m.get('severity_upgrade_allowed')!r})",
            )
            self.assertIs(
                m.get("evidence_matrix_contributes"), False,
                f"manifest {name}: evidence_matrix_contributes must be false "
                f"(got {m.get('evidence_matrix_contributes')!r})",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
