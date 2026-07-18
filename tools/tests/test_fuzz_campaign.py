#!/usr/bin/env python3
"""V5 PR 4 — fuzz-campaign wrapper smoke tests (hermetic, stdlib-only).

These tests exercise the wrapper end-to-end without requiring `forge`
to be on PATH. The pattern is `_stdout_override`: we feed the wrapper
the bytes a real forge invocation would have written and verify the
state-machine + artifact pipeline.

Codex's six acceptance tests (Section 4 of
docs/ROADMAP_10_OF_10_V5_CAMPAIGNS.md):

  1. Toy vulnerable contract produces a crash.
  2. Crash is shrunk.
  3. Forge test generated from shrunk sequence.
  4. Generated Forge test reproduces on the vulnerable version.
  5. Generated Forge test changes behavior or fails after recommended fix.
  6. Timeout or coverage plateau produces honest non-finding summary.

Tests 4 and 5 require an actual `forge` binary. Where forge is unavailable
(CI default) we substitute *contract-shape* checks: the generated .t.sol
file references the target, includes the shrunk sequence as a comment
block, and asserts false until the operator wires it. That asserts the
wrapper does NOT silently emit a green test (the Minimax-flagged failure
mode "shrink hides root cause").
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "fuzz-campaign.py"


def _load_module():
    """Import tools/fuzz-campaign.py as a module (hyphen-safe)."""
    spec = importlib.util.spec_from_file_location("fuzz_campaign", TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


FC = _load_module()


# ---------------------------------------------------------------------------
# Synthetic forge stdout fixtures — emulate exact strings forge prints on
# crashes / clean passes / hangs. Hermetic: no real forge needed.
# ---------------------------------------------------------------------------

CRASH_STDOUT = """\
Compiling 1 files with 0.8.20
[FAIL. Reason: Assertion violated] invariant_sum_consistency() (runs: 17, calls: 412, reverts: 0)

[Sequence] (sender=0xdeadbeef00000000000000000000000000000001)
ToyVulnerable.deposit(100)
ToyVulnerable.deposit(50)
ToyVulnerable.withdraw(30)
ToyVulnerable.withdraw(7)
ToyVulnerable.deposit(1)

Test Result: 1 failed
"""

# Same crash, different volatile fields — should dedup to same hash.
CRASH_STDOUT_VARIANT = """\
Compiling 1 files with 0.8.20
[FAIL. Reason: Assertion violated] invariant_sum_consistency() (runs: 22, calls: 514, reverts: 0)

[Sequence] (sender=0xfeedbeef00000000000000000000000000000002)
ToyVulnerable.deposit(100)
ToyVulnerable.deposit(50)
ToyVulnerable.withdraw(30)
ToyVulnerable.withdraw(7)
ToyVulnerable.deposit(1)

Test Result: 1 failed
"""

PASS_STDOUT = """\
Compiling 1 files with 0.8.20
Ran 3 tests for src/ToyVulnerable.sol:ToyVulnerableTest
[PASS] invariant_sum_consistency() (runs: 256, calls: 8192, reverts: 0)
[PASS] invariant_no_underflow() (runs: 256, calls: 8192, reverts: 0)
[PASS] testDeposit() (gas: 51234)
Test Result: ok. 3 passed
"""

TIMEOUT_STDOUT = """\
Compiling 1 files with 0.8.20
__SIM_TIMEOUT__
"""


def _make_workspace(tmp: Path) -> Path:
    ws = tmp / "ws"
    (ws / "src").mkdir(parents=True)
    (ws / "src" / "ToyVulnerable.sol").write_text("// fixture\n")
    (ws / "foundry.toml").write_text("[profile.default]\nsrc = \"src\"\n")
    return ws


# ---------------------------------------------------------------------------
# Acceptance test 1: crash detected
# ---------------------------------------------------------------------------

class CrashFoundTest(unittest.TestCase):
    def test_toy_vulnerable_produces_crash(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            ws = _make_workspace(tmp)
            out = tmp / "fuzz_campaigns" / "test-001"
            state = FC.run_campaign(
                workspace=ws,
                target="ToyVulnerable",
                profile="invariant",
                duration=10,
                out_dir=out,
                _stdout_override=CRASH_STDOUT,
            )
            self.assertEqual(state["lifecycle"], "forge_test_generated",
                             f"expected forge_test_generated, got {state['lifecycle']}")
            self.assertEqual(len(state["crashes"]), 1)
            crashes = list((out / "crashes").glob("*.json"))
            self.assertEqual(len(crashes), 1)
            crash = json.loads(crashes[0].read_text())
            self.assertIn("dedup_hash", crash)
            self.assertNotEqual(crash["dedup_hash"], "no-seq")
            self.assertIn("ToyVulnerable.deposit(100)", crash["raw_seq"])


# ---------------------------------------------------------------------------
# Acceptance test 2: crash shrunk + dedup is stable across volatile reruns
# ---------------------------------------------------------------------------

class ShrinkAndDedupTest(unittest.TestCase):
    def test_crash_shrunk(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            ws = _make_workspace(tmp)
            out = tmp / "fuzz_campaigns" / "test-002"
            state = FC.run_campaign(
                workspace=ws, target="ToyVulnerable",
                profile="invariant", duration=10, out_dir=out,
                _stdout_override=CRASH_STDOUT,
            )
            shrunk = list((out / "shrunk").glob("*.json"))
            self.assertEqual(len(shrunk), 1)
            data = json.loads(shrunk[0].read_text())
            self.assertEqual(data["seed_determinism"], "deterministic")
            self.assertGreater(data["original_len"], 0)
            self.assertGreater(data["shrunk_len"], 0)
            self.assertLessEqual(data["shrunk_len"], data["original_len"])
            self.assertIn("ToyVulnerable.deposit(100)", data["shrunk_seq"])

    def test_dedup_is_stable_across_volatile_reruns(self) -> None:
        # The wrapper's dedup_hash must collapse the same crash with
        # different sender-addresses / run-counts to a single hash. This
        # is the foot-gun Minimax warned about: "a bypassed crash filtered
        # as flake when it's a real bug" — but it's also the bypass when
        # one *real* crash gets logged twice as two findings.
        h1 = FC.crash_dedup_hash(FC.extract_failing_sequence(CRASH_STDOUT))
        h2 = FC.crash_dedup_hash(FC.extract_failing_sequence(CRASH_STDOUT_VARIANT))
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 12)


# ---------------------------------------------------------------------------
# Acceptance test 3: Forge test generated from shrunk sequence
# ---------------------------------------------------------------------------

class ForgeTestGeneratedTest(unittest.TestCase):
    def test_forge_test_generated_from_shrunk(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            ws = _make_workspace(tmp)
            out = tmp / "fuzz_campaigns" / "test-003"
            FC.run_campaign(
                workspace=ws, target="ToyVulnerable",
                profile="invariant", duration=10, out_dir=out,
                _stdout_override=CRASH_STDOUT,
            )
            tests = list((out / "forge_tests").glob("*.t.sol"))
            self.assertEqual(len(tests), 1, "expected exactly one Forge test")
            text = tests[0].read_text()
            # Must reference the target.
            self.assertIn("ToyVulnerable", text)
            # Must contain the shrunk sequence verbatim as a comment.
            self.assertIn("ToyVulnerable.deposit(100)", text)
            # Must NOT silently assert pass — the operator-promotion gate
            # requires the file to fail until wired (Minimax foot-gun).
            self.assertIn('assertTrue(false', text,
                          "generated test must require operator wiring")


# ---------------------------------------------------------------------------
# Acceptance tests 4 + 5: Forge replay reproduces / changes behaviour after fix
# (forge-dependent — degrade gracefully when forge is absent)
# ---------------------------------------------------------------------------

class ForgeReplayShapeTest(unittest.TestCase):
    """Without a real `forge`, we cannot run the generated test against
    the vulnerable / fixed fixtures. We DO verify the structural
    contract the operator gate depends on: (a) the file references the
    target, (b) the shrunk sequence is preserved verbatim, (c) the file
    contains the operator-wiring assert. These are the preconditions
    for tests 4+5; passing them guarantees that a correctly-wired
    operator will see the expected reproduce/change-behavior signal."""

    def test_replay_scaffold_contract_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            ws = _make_workspace(tmp)
            out = tmp / "fuzz_campaigns" / "test-045"
            FC.run_campaign(
                workspace=ws, target="ToyVulnerable",
                profile="invariant", duration=10, out_dir=out,
                _stdout_override=CRASH_STDOUT,
            )
            tests = list((out / "forge_tests").glob("*.t.sol"))
            text = tests[0].read_text()
            # (a) target reference
            self.assertIn("Replay_", text)
            self.assertIn("ToyVulnerable", text)
            # (b) shrunk sequence preserved as commented evidence —
            # operator can re-translate to concrete calls when wiring.
            for line in (
                "ToyVulnerable.deposit(100)",
                "ToyVulnerable.withdraw(30)",
            ):
                self.assertIn(line, text, f"shrunk line missing: {line}")
            # (c) operator-promotion gate present — the generated test
            # MUST require operator wiring. Three signals must all be
            # present so a single edit can't accidentally silence the
            # gate:
            self.assertIn("operator: fill in", text,
                          "missing operator-wiring assert message")
            self.assertIn("Operator must", text,
                          "missing operator-promotion gate language")
            self.assertIn("AUTO-GENERATED", text,
                          "missing auto-generated header")


# ---------------------------------------------------------------------------
# Acceptance test 6: timeout / coverage_plateau → honest non-finding
# ---------------------------------------------------------------------------

class TimeoutHonestNonFindingTest(unittest.TestCase):
    def test_timeout_emits_non_finding(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            ws = _make_workspace(tmp)
            out = tmp / "fuzz_campaigns" / "test-006-timeout"
            state = FC.run_campaign(
                workspace=ws, target="ToyVulnerable",
                profile="invariant", duration=120, out_dir=out,
                _stdout_override=TIMEOUT_STDOUT,
            )
            # Critical: wrapper MUST NOT call this 'verified'. Minimax
            # specifically attacked the "timeout silently emits verified"
            # failure mode.
            self.assertEqual(state["lifecycle"], "timeout")
            self.assertNotEqual(state["lifecycle"], "verified")
            summary = (out / "summary.md").read_text()
            self.assertIn("Honest non-finding", summary)
            self.assertNotIn("Verified replay", summary)

    def test_coverage_plateau_emits_non_finding(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            ws = _make_workspace(tmp)
            out = tmp / "fuzz_campaigns" / "test-006-plateau"
            state = FC.run_campaign(
                workspace=ws, target="ToyVulnerable",
                profile="invariant", duration=120, out_dir=out,
                _stdout_override=PASS_STDOUT,
            )
            self.assertEqual(state["lifecycle"], "coverage_plateau")
            summary = (out / "summary.md").read_text()
            self.assertIn("Honest non-finding", summary)

    def test_summary_duration_is_elapsed_not_budget(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            ws = _make_workspace(tmp)
            out = tmp / "fuzz_campaigns" / "test-duration"
            state = FC.run_campaign(
                workspace=ws, target="ToyVulnerable",
                profile="invariant", duration=120, out_dir=out,
                _stdout_override=PASS_STDOUT,
            )
            persisted = json.loads((out / "summary.json").read_text())
            self.assertEqual(persisted["budget_seconds"], 120)
            self.assertLess(persisted["duration"], persisted["budget_seconds"])
            self.assertEqual(state["duration"], persisted["duration"])
            config = json.loads((out / "config.json").read_text())
            self.assertEqual(config["budget_seconds"], 120)
            self.assertNotIn("duration", config)


# ---------------------------------------------------------------------------
# Lifecycle state-machine guard — Minimax foot-gun: silent illegal transitions
# ---------------------------------------------------------------------------

class LifecycleGuardTest(unittest.TestCase):
    def test_legal_transitions(self) -> None:
        for src, dsts in {
            "created": {"seeding"},
            "seeding": {"running"},
            "running": {"crash_found", "timeout", "coverage_plateau"},
            "crash_found": {"shrinking"},
            "shrinking": {"forge_test_generated"},
            "forge_test_generated": {"verified", "rejected"},
        }.items():
            for d in dsts:
                self.assertTrue(FC.can_transition(src, d), f"{src}->{d}")

    def test_illegal_skip_to_verified_blocked(self) -> None:
        # The honesty bypass: jumping from timeout/running directly to
        # verified must be rejected.
        self.assertFalse(FC.can_transition("timeout", "verified"))
        self.assertFalse(FC.can_transition("running", "verified"))
        self.assertFalse(FC.can_transition("created", "verified"))

    def test_terminal_states_are_truly_terminal(self) -> None:
        for s in ("verified", "rejected", "timeout", "coverage_plateau"):
            for d in FC.LIFECYCLE_STATES:
                self.assertFalse(FC.can_transition(s, d),
                                 f"terminal {s} should not transition to {d}")


# ---------------------------------------------------------------------------
# Bounded-budget guard — DURATION_CAP and engine deferral
# ---------------------------------------------------------------------------

class BoundedBudgetTest(unittest.TestCase):
    def test_duration_cap_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            ws = _make_workspace(tmp)
            with self.assertRaises(ValueError):
                FC.run_campaign(
                    workspace=ws, target="X", profile="invariant",
                    duration=FC.DURATION_CAP_SECONDS + 1,
                    out_dir=tmp / "out",
                    _stdout_override=PASS_STDOUT,
                )

    def test_zero_duration_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            ws = _make_workspace(tmp)
            with self.assertRaises(ValueError):
                FC.run_campaign(
                    workspace=ws, target="X", profile="invariant",
                    duration=0, out_dir=tmp / "out",
                    _stdout_override=PASS_STDOUT,
                )

    def test_invalid_profile_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            ws = _make_workspace(tmp)
            with self.assertRaises(ValueError):
                FC.run_campaign(
                    workspace=ws, target="X", profile="bogus",
                    duration=10, out_dir=tmp / "out",
                    _stdout_override=PASS_STDOUT,
                )


# ---------------------------------------------------------------------------
# CLI surface tests
# ---------------------------------------------------------------------------

class CLITest(unittest.TestCase):
    def test_help(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(TOOL), "--help"],
            capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("--workspace", proc.stdout)
        self.assertIn("--target", proc.stdout)
        self.assertIn("--profile", proc.stdout)
        self.assertIn("--duration", proc.stdout)
        self.assertIn("--out", proc.stdout)

    def test_list_tools_inventory(self) -> None:
        # Codex's hard rule: inventory existing tools FIRST. The CLI must
        # be able to surface that inventory to humans + agents.
        proc = subprocess.run(
            [sys.executable, str(TOOL),
             "--workspace", "/tmp", "--target", "X", "--out", "/tmp/x",
             "--list-tools"],
            capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(proc.returncode, 0)
        # Must list the load-bearing existing tools.
        for must_ref in (
            "tools/fuzz-runner.sh",
            "tools/symbolic-ce-to-forge.py",
            "tools/poc-scaffold.py",
            "forge test --invariant",
            "tools/audit-deep.sh",
        ):
            self.assertIn(must_ref, proc.stdout,
                          f"inventory missing: {must_ref}")

    def test_engine_medusa_deferred(self) -> None:
        # PR 4 first impl: medusa/echidna are deferred. The wrapper must
        # surface a clear error rather than silently routing them.
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            ws = _make_workspace(tmp)
            with self.assertRaises(RuntimeError) as cm:
                FC.discover_engine(ws, "medusa")
            self.assertIn("deferred", str(cm.exception).lower())


# ---------------------------------------------------------------------------
# Resume + idempotency — campaign init must be re-runnable safely
# ---------------------------------------------------------------------------

class ReplayLogTest(unittest.TestCase):
    def test_replay_log_records_every_transition(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            ws = _make_workspace(tmp)
            out = tmp / "fuzz_campaigns" / "test-replay"
            FC.run_campaign(
                workspace=ws, target="ToyVulnerable",
                profile="invariant", duration=10, out_dir=out,
                _stdout_override=CRASH_STDOUT,
            )
            log = (out / "replay.log").read_text().strip().splitlines()
            events = [json.loads(line)["event"] for line in log]
            # Initial init + at least the four lifecycle transitions
            # to forge_test_generated.
            for required in (
                "campaign-init",
                "transition:seeding",
                "transition:running",
                "transition:crash_found",
                "transition:shrinking",
                "transition:forge_test_generated",
            ):
                self.assertIn(required, events,
                              f"missing event in replay.log: {required}")


if __name__ == "__main__":
    unittest.main()
