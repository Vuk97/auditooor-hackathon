"""I-10 (PR #158): stage_orient must escalate real errors to FAIL.

Background — quoted from PR #158, I-10:
    `orient` stage `skill-state.yaml` init failure swallowed as SUCCESS_WARN.
    After ASSET_PLAN unblocked intake, `orient` ran 189s and emitted
    `SUCCESS_WARN skill-state init failed, topology partial (0 ambiguous,
    19 unresolved, 1 errors)`. "skill-state init failed" with 1 error is
    a real problem but stage downstream sees SUCCESS_WARN and proceeds.
    19 unresolved deployment-topology entries means the
    `monitoring/live_checks.generated.json` is unreliable for live-checks
    downstream.
    Fix: stage runner should escalate "X errors" to FAIL or produce a
    per-error breakdown, not bury under SUCCESS_WARN.

This test pins the new classifier behavior:
  1. `errors > 0` from topology summary → FAIL with per-error breakdown
     unless every entry is a deploy lookup timeout and `rpc_ready=false`;
     that specific source-only/no-RPC setup is a loud warning.
  2. `skill-state init failed` (rc != 0) → FAIL with rc breakdown.
  3. `ambiguous` / `unresolved` alone (no errors) stay as SUCCESS_WARN —
     those are expected during early triage and were never the bug.
  4. The classifier preserves existing FAIL signals (CCIA missing, etc.).
  5. Pure-warning input continues to return SUCCESS_WARN (no regression).
"""
from __future__ import annotations

import importlib.util
import sys
import types
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
ENGAGE = REPO / "tools" / "engage.py"


def _load_engage_module() -> types.ModuleType:
    tools_dir = str(REPO / "tools")
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    spec = importlib.util.spec_from_file_location("engage", ENGAGE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ClassifyOrientOutcomeTest(unittest.TestCase):
    """Direct-helper tests on `_classify_orient_outcome`."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.engage = _load_engage_module()

    def test_topology_errors_escalate_to_fail(self) -> None:
        """The exact symptom from PR #158 I-10: 1 topology error must FAIL,
        not SUCCESS_WARN."""
        status = self.engage._classify_orient_outcome(
            failures=[],
            hard_failures=["topology builder errors (1 contract(s); 0 ambiguous, 19 unresolved)"],
            warnings=[],
        )
        self.assertTrue(
            status.startswith("FAIL"),
            f"errors > 0 must escalate to FAIL, got: {status!r}",
        )
        self.assertIn("topology builder errors", status)
        self.assertIn("1 contract(s)", status)
        self.assertIn("19 unresolved", status)

    def test_skill_state_init_failure_escalates_to_fail(self) -> None:
        """`skill-state init` rc != 0 leaves `.skill_state.yaml` absent;
        downstream stages consume that file. Must FAIL, not SUCCESS_WARN."""
        status = self.engage._classify_orient_outcome(
            failures=[],
            hard_failures=["skill-state init failed (rc=2)"],
            warnings=["orient-from-audits failed"],
        )
        self.assertTrue(
            status.startswith("FAIL"),
            f"skill-state init failure must escalate to FAIL, got: {status!r}",
        )
        self.assertIn("skill-state init failed", status)
        self.assertIn("rc=2", status)

    def test_ambiguous_or_unresolved_alone_remains_success_warn(self) -> None:
        """Ambiguous / unresolved without `errors` are expected during
        early triage; don't regress them to FAIL."""
        status = self.engage._classify_orient_outcome(
            failures=[],
            hard_failures=[],
            warnings=["topology partial (0 ambiguous, 19 unresolved, 0 errors)"],
        )
        self.assertTrue(
            status.startswith("SUCCESS_WARN"),
            f"ambiguous/unresolved-only must remain SUCCESS_WARN, got: {status!r}",
        )

    def test_pure_success_no_signals(self) -> None:
        status = self.engage._classify_orient_outcome(
            failures=[], hard_failures=[], warnings=[],
        )
        self.assertEqual(status, "SUCCESS")

    def test_existing_fail_signals_still_propagate(self) -> None:
        """`failures` (e.g. missing CCIA) was the original FAIL channel —
        the new helper must not regress it."""
        status = self.engage._classify_orient_outcome(
            failures=["ccia missing"],
            hard_failures=[],
            warnings=["skill-state missing"],
        )
        self.assertTrue(status.startswith("FAIL"))
        self.assertIn("ccia missing", status)

    def test_combined_failures_and_hard_failures_concatenate(self) -> None:
        """When both fail-channels fire, every per-error category is shown
        so the operator sees the full breakdown."""
        status = self.engage._classify_orient_outcome(
            failures=["ccia failed"],
            hard_failures=[
                "skill-state init failed (rc=1)",
                "topology builder errors (3 contract(s); 0 ambiguous, 0 unresolved)",
            ],
            warnings=["orient-from-audits missing"],
        )
        self.assertTrue(status.startswith("FAIL"))
        self.assertIn("ccia failed", status)
        self.assertIn("skill-state init failed", status)
        self.assertIn("topology builder errors", status)
        # "3 contract(s)" not truncated
        self.assertIn("3 contract(s)", status)


class StageOrientSourceContractTest(unittest.TestCase):
    """Pin the in-source contract: stage_orient must collect a
    `hard_failures` list and route it through `_classify_orient_outcome`.
    Catches future refactors that re-bury the signals under warnings."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.src = ENGAGE.read_text()

    def test_classifier_helper_present(self) -> None:
        self.assertIn("def _classify_orient_outcome(", self.src)

    def test_strict_pipeline_promotes_success_warn_to_fail(self) -> None:
        """Strict ordered runs must not let any stage warning continue."""
        self.assertIn(
            'os.environ.get("PIPELINE_STRICT") == "1"',
            self.src,
        )
        self.assertIn(
            'status = f"FAIL strict-pipeline: {status}"',
            self.src,
        )

    def test_source_only_topology_disposition_is_explicit(self) -> None:
        self.assertIn('os.environ.get("AUDITOOOR_SOURCE_ONLY") == "1"', self.src)
        self.assertIn('"mode": "github-source-only"', self.src)
        self.assertIn('"live_state": "not_collected"', self.src)
        self.assertIn('SUCCESS source-only live state not collected', self.src)

    def test_dispatch_gate_hard_stop_is_not_softened(self) -> None:
        self.assertIn('r"\\[HARD\\]|HARD STOP|prior_audits/.*DIGEST', self.src)
        self.assertNotIn('r"HARD STOP|brief empty', self.src)

    def test_stage_orient_uses_hard_failures(self) -> None:
        # The function must declare and use a `hard_failures` channel.
        # This guards against a regression where someone reverts the
        # `errors > 0` path back to a `warnings.append(...)`.
        orient_start = self.src.find("def stage_orient(")
        self.assertGreater(orient_start, 0)
        next_def = self.src.find("\ndef ", orient_start + 1)
        self.assertGreater(next_def, orient_start)
        body = self.src[orient_start:next_def]
        self.assertIn("hard_failures", body)
        self.assertIn("hard_failures.append", body)
        # Errors-from-topology branch must keep a hard-failure path while
        # allowing timeout-only/no-RPC source-review workspaces to warn.
        self.assertIn("error_entries", body)
        self.assertIn("len(error_entries) == errors", body)
        self.assertIn("timeout_only", body)
        self.assertRegex(
            body,
            r"if timeout_only:\s*\n\s*warnings\.append",
            "timeout-only topology errors with rpc_ready=no should warn",
        )
        self.assertRegex(
            body,
            r"else:\s*\n\s*hard_failures\.append",
            "non-timeout topology errors must still escalate to hard_failures",
        )
        # skill-state nonzero rc must also route to hard_failures.
        self.assertRegex(
            body,
            r"hard_failures\.append\(f?\"skill-state init failed",
            "skill-state init nonzero rc must escalate to hard_failures",
        )

    def test_stage_orient_returns_via_classifier(self) -> None:
        orient_start = self.src.find("def stage_orient(")
        next_def = self.src.find("\ndef ", orient_start + 1)
        body = self.src[orient_start:next_def]
        self.assertIn("_classify_orient_outcome(", body)


if __name__ == "__main__":
    unittest.main()
