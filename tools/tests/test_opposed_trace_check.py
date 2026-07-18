"""Unit tests for the HACKERMAN_V3 opposed-trace proof gate.

Acceptance tests required by the spec:
  AT-1: Spark-like draft with only watcher false-confirmation and no
        watchtower/refund defense -> FAIL with fail-unopposed-trace.
  AT-2: Draft enumerating lower-timelock refunds showing "defender wins"
        -> FAIL with fail-defender-wins (cannot claim direct loss).
  AT-3: Draft including defenses AND showing attacker still wins
        -> PASS (pass-defenses-covered).

Additional regression cases mirror the pattern from the sibling tools
(defense-in-depth-traversal-check, non-self-impact-check).
"""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "opposed_trace_check",
    ROOT / "tools" / "opposed-trace-check.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _workspace() -> Path:
    root = Path(tempfile.mkdtemp(prefix="opposed_trace_"))
    (root / "submissions" / "paste_ready").mkdir(parents=True)
    (root / "poc-tests" / "lead1").mkdir(parents=True)
    return root


def _draft(body: str, filename: str = "draft-HIGH.md") -> Path:
    root = _workspace()
    draft = root / "submissions" / "paste_ready" / filename
    draft.write_text(body, encoding="utf-8")
    return draft


def _draft_with_poc(body: str, poc_source: str, filename: str = "draft-HIGH.md") -> tuple[Path, str]:
    root = _workspace()
    poc_dir = root / "poc-tests" / "lead1"
    (poc_dir / "poc_test.go").write_text(poc_source, encoding="utf-8")
    body_with_ref = body + f"\nPoC: `poc-tests/lead1`\n"
    draft = root / "submissions" / "paste_ready" / filename
    draft.write_text(body_with_ref, encoding="utf-8")
    return draft, str(poc_dir)


# ---------------------------------------------------------------------------
# AT-1: Spark LEAD1 shape - watcher false-confirmation, no defense enumerated
# ---------------------------------------------------------------------------

class AcceptanceTest1_UnoposedTrace(unittest.TestCase):
    """AT-1: Spark-like chain-watcher draft with no defense simulated."""

    def test_spark_lead1_no_defense_fails_unopposed(self) -> None:
        """High draft claiming Direct Loss where only the watcher bug is shown,
        with no watchtower / refund / timelock path simulated -> fail-unopposed-trace."""
        body = """\
# Chain-watcher validation gap in Spark cooperative-exit flow leads to direct loss of funds

## Severity
- Severity: High

## Summary
The chain-watcher validates exit transactions by comparing the txid of the
cooperative-exit transaction against the stored exit_txid. The comparison is
performed by a simple equality check at watch_chain.go:842. An attacker can
broadcast an unrelated transaction that matches the lower-level hash prefix
check, causing the watcher to consider an unrelated (attacker-controlled)
transaction as the valid cooperative exit. This bypasses the cooperative-exit
confirmation, permanently losing the receiver's funds.

## Impact Contract
- selected_impact: Direct loss of funds
- severity_tier: High
- listed_impact_proven: true
- evidence_class: executed_poc
- oos_traps: []
- stop_condition: do_not_claim_critical_unless_extended

## Proof of Concept

```go
func TestWatcherFalseConfirmation(t *testing.T) {
    // Attacker crafts unrelated txid
    fakeTxID := buildFakeTxID()
    // Watcher erroneously accepts it
    result := watcher.ConfirmCoopExit(ctx, fakeTxID)
    // Receiver's funds are now permanently lost
    assert.Equal(t, "confirmed", result)
}
```

Result: attacker path succeeds.
"""
        draft = _draft(body)
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1, f"Expected exit 1, got {rc}; verdict={payload['verdict']}")
        self.assertEqual(payload["verdict"], "fail-unopposed-trace")
        self.assertIn("direct loss", payload["evidence"]["trigger_hits"][0].lower())

    def test_high_theft_claim_no_defense_mention_fails(self) -> None:
        """High draft claiming theft of funds with no defense enumerated."""
        body = """\
# Reentrancy in withdraw leads to theft of funds

## Severity
- Severity: High

## Summary
The withdraw function transfers ETH before updating the balance.
An attacker re-enters and drains the contract.

## Impact Contract
- selected_impact: Theft of funds
- listed_impact_proven: true
"""
        draft = _draft(body)
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-unopposed-trace")


# ---------------------------------------------------------------------------
# AT-2: Defenses enumerated but defender wins -> fail-defender-wins
# ---------------------------------------------------------------------------

class AcceptanceTest2_DefenderWins(unittest.TestCase):
    """AT-2: Lower-timelock refund is enumerated and defender wins."""

    def test_defender_wins_blocks_direct_loss_claim(self) -> None:
        """Draft enumerates lower-timelock refund and shows defender wins.
        Direct Loss cannot be claimed -> fail-defender-wins."""
        body = """\
# Chain-watcher gap in Spark allows unauthorized cooperative exit

## Severity
- Severity: High

## Summary
...

## Impact Contract
- selected_impact: Direct loss of funds
- listed_impact_proven: true

## Protocol-Owned Defenses Considered

| Defense | Code path | Expected protection | Included in PoC? | Result | If omitted, why safe? |
|---|---|---|---|---|---|
| Lower-timelock connector refund | watch_chain.go:1210 | Receiver can claim refund via lower timelock if exit is invalid | Yes | Defender wins: refund succeeds, funds recovered | N/A |

The lower-timelock refund path succeeds and funds are recovered.
Outcome: defender wins.
"""
        draft = _draft(body)
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1, f"Expected exit 1; verdict={payload['verdict']}")
        self.assertEqual(payload["verdict"], "fail-defender-wins")

    def test_protocol_prevents_loss_blocks_claim(self) -> None:
        """Draft shows protocol prevents the loss -> fail-defender-wins."""
        body = """\
# Missing guard leads to direct loss of funds

## Severity
- Severity: Critical

The watcher detects the attack. Protocol prevents the loss. No loss occurs.
The refund succeeds and funds are recovered.

## Impact Contract
- selected_impact: Direct loss of funds
- listed_impact_proven: true
"""
        draft = _draft(body, filename="draft-CRITICAL.md")
        rc, payload = mod.run(draft, severity="Critical")
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-defender-wins")


# ---------------------------------------------------------------------------
# AT-3: Defenses covered AND attacker still wins -> PASS
# ---------------------------------------------------------------------------

class AcceptanceTest3_AttackerWinsDefeatingDefenses(unittest.TestCase):
    """AT-3: Defenses enumerated and attacker still wins -> pass-defenses-covered."""

    def test_attacker_wins_despite_defenses_passes(self) -> None:
        """Draft enumerates watchtower and lower-timelock refund, shows attacker
        wins despite both -> pass-defenses-covered."""
        body = """\
# Chain-watcher gap leads to direct loss of funds

## Severity
- Severity: High

## Impact Contract
- selected_impact: Direct loss of funds
- listed_impact_proven: true

## Protocol-Owned Defenses Considered

| Defense | Code path | Expected protection | Included in PoC? | Result | If omitted, why safe? |
|---|---|---|---|---|---|
| Watchtower sweep | watchtower/sweep.go:44 | Detect double-exit and slash | Yes | Defense fails: attacker's txid bypasses sweep check | N/A |
| Lower-timelock connector refund | watch_chain.go:1210 | Receiver reclaims via lower timelock | Yes | Defense fails: refund is blocked by the attacker's prior claim | N/A |

Outcome: attacker wins. The watchtower fails to catch the forged txid.
The lower-timelock refund is blocked. Funds are permanently lost.
"""
        draft = _draft(body)
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0, f"Expected exit 0; verdict={payload['verdict']}")
        self.assertEqual(payload["verdict"], "pass-defenses-covered")

    def test_attacker_still_wins_signal_in_poc_passes(self) -> None:
        """Attacker-wins signal comes from the PoC source file."""
        body = """\
# Reentrancy leads to loss of funds

## Severity
- Severity: High

## Protocol-Owned Defenses Considered
The pause mechanism is considered below.

## Impact Contract
- selected_impact: Loss of funds
- listed_impact_proven: true
"""
        poc_source = """\
package poc_test

func TestReentrancy(t *testing.T) {
    // Pause is bypassed because the pauser role was revoked.
    // Attacker still wins despite the pause mechanism.
    result := attack.Execute()
    assert.Equal(t, "drained", result)
}
"""
        draft, poc_dir = _draft_with_poc(body, poc_source)
        rc, payload = mod.run(draft, poc_dir=poc_dir)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-defenses-covered")


# ---------------------------------------------------------------------------
# Scope / severity tests
# ---------------------------------------------------------------------------

class ScopeTests(unittest.TestCase):
    def test_medium_severity_trigger_is_advisory_warn(self) -> None:
        """Tiered model: a Medium draft with a trigger keyword and no defense
        evidence gets the mandatory advisory verdict warn-unopposed-trace and
        the run still passes (rc=0, non-blocking)."""
        body = "Severity: Medium\ndirect loss of funds claimed here."
        draft = _draft(body, filename="draft-MEDIUM.md")
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0, "Medium advisory must NOT hard-block (rc must stay 0)")
        self.assertEqual(payload["verdict"], "warn-unopposed-trace")
        self.assertEqual(payload["enforcement"], "advisory")

    def test_low_severity_trigger_is_advisory_warn(self) -> None:
        """Tiered model: a Low draft with a trigger keyword and no defense
        evidence gets warn-unopposed-trace; the run still passes (rc=0)."""
        body = "Severity: Low\ndirect loss of funds."
        draft = _draft(body)
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0, "Low advisory must NOT hard-block (rc must stay 0)")
        self.assertEqual(payload["verdict"], "warn-unopposed-trace")
        self.assertEqual(payload["enforcement"], "advisory")

    def test_medium_temporary_freeze_is_advisory_warn(self) -> None:
        """A Medium temporary-freeze claim is just as unproven if a watchtower
        path would unfreeze it - the question is asked at every severity."""
        body = """\
Severity: Medium

The bug causes funds frozen until the next epoch boundary; the receiver
cannot move the deposit while the stale flag is set.
"""
        draft = _draft(body, filename="freeze-MEDIUM.md")
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "warn-unopposed-trace")
        self.assertEqual(payload["enforcement"], "advisory")

    def test_no_trigger_keyword_out_of_scope(self) -> None:
        """A draft with genuinely no severity keyword still returns
        pass-out-of-scope at any severity."""
        body = "Severity: High\nThis is a reentrancy finding with minor accounting impact."
        draft = _draft(body)
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_no_trigger_keyword_medium_out_of_scope(self) -> None:
        """Medium draft with no trigger keyword - still pass-out-of-scope."""
        body = "Severity: Medium\nAn event ordering quirk with no fund impact."
        draft = _draft(body, filename="quirk-MEDIUM.md")
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_medium_not_applicable_honored(self) -> None:
        """The not_applicable honest escape is honored at every severity."""
        body = """\
Severity: Medium

The bug causes funds frozen until manual recovery.

## Impact Contract
- opposed_trace_coverage: not_applicable
"""
        draft = _draft(body, filename="na-MEDIUM.md")
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-not-applicable")

    def test_medium_rebuttal_honored(self) -> None:
        """A valid rebuttal marker is honored at Medium severity."""
        body = """\
Severity: Medium

Funds frozen briefly.

<!-- opposed-trace-rebuttal: no watchtower/refund path exists for this asset; source-backed by SCOPE.md:9 -->
"""
        draft = _draft(body, filename="reb-MEDIUM.md")
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_high_unopposed_still_hard_fails(self) -> None:
        """HIGH+ enforcement is unchanged: an unopposed HIGH draft hard-fails."""
        body = "Severity: High\ndirect loss of funds, no defenses enumerated."
        draft = _draft(body)
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1, "HIGH+ must still hard-fail (rc=1)")
        self.assertEqual(payload["verdict"], "fail-unopposed-trace")
        self.assertEqual(payload["enforcement"], "hard")

    def test_severity_from_filename(self) -> None:
        body = "direct loss of funds.\nNo defenses enumerated."
        draft = _draft(body, filename="my-finding-high.md")
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-unopposed-trace")
        self.assertEqual(payload["severity_source"], "filename")


# ---------------------------------------------------------------------------
# Rebuttal and not-applicable
# ---------------------------------------------------------------------------

class RebuttalTests(unittest.TestCase):
    def test_valid_rebuttal_passes(self) -> None:
        body = """\
# Bug leads to direct loss of funds

Severity: High

There is no protocol-owned defense on this attack surface because the asset is
fully user-controlled with no protocol rescue path.

<!-- opposed-trace-rebuttal: no rescue/refund/watchtower path exists for this asset class; source-backed by SCOPE.md:14 -->
"""
        draft = _draft(body)
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_empty_rebuttal_falls_through(self) -> None:
        """An empty rebuttal marker is not accepted and falls through to fail."""
        body = """\
# Bug leads to direct loss of funds

Severity: High

<!-- opposed-trace-rebuttal: -->
"""
        draft = _draft(body)
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertIn(payload["verdict"], ("fail-unopposed-trace", "fail-defender-wins"))

    def test_oversized_rebuttal_falls_through(self) -> None:
        """A rebuttal reason >200 chars is ignored."""
        long_reason = "x" * 201
        body = f"Severity: High\ndirect loss of funds.\n<!-- opposed-trace-rebuttal: {long_reason} -->\n"
        draft = _draft(body)
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)

    def test_not_applicable_annotation_passes(self) -> None:
        body = """\
# Bug leads to direct loss of funds

Severity: High

## Impact Contract
- selected_impact: Direct loss of funds
- opposed_trace_coverage: not_applicable
"""
        draft = _draft(body)
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-not-applicable")


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class ErrorHandlingTests(unittest.TestCase):
    def test_missing_file_returns_error(self) -> None:
        rc, payload = mod.run(Path("/no/such/file.md"))
        self.assertEqual(rc, 2)
        self.assertEqual(payload["verdict"], "error")

    def test_schema_version_present(self) -> None:
        body = "Severity: High\nDirect loss of funds.\nWatcher fails."
        draft = _draft(body)
        _rc, payload = mod.run(draft)
        self.assertIn("schema", payload)
        self.assertIn("gate", payload)
        self.assertEqual(payload["gate"], "R-OPPOSED-TRACE")


# ---------------------------------------------------------------------------
# CLI / stdout JSON test
# ---------------------------------------------------------------------------

class CliTest(unittest.TestCase):
    def test_cli_json_output(self) -> None:
        import subprocess
        import sys
        import json

        body = "Severity: High\nDirect loss of funds.\n"
        draft = _draft(body)
        proc = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "opposed-trace-check.py"), str(draft), "--json"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertIn(proc.returncode, (0, 1))
        payload = json.loads(proc.stdout)
        self.assertIn("verdict", payload)
        self.assertIn("schema", payload)


if __name__ == "__main__":
    unittest.main(verbosity=2)
