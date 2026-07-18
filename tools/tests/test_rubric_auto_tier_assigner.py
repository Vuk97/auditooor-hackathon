# r36-rebuttal: lane-RULE-63 registered in .auditooor/agent_pathspec.json via tools/agent-pathspec-register.py
"""Unit tests for Rule 63 Auto-Tier-Assignment (Check #115)."""

from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from typing import Optional


ROOT = Path(__file__).resolve().parents[2]

_spec = importlib.util.spec_from_file_location(
    "rubric_auto_tier_assigner",
    ROOT / "tools" / "rubric-auto-tier-assigner.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------
DYDX_SEVERITY_MD = """# Severity - dYdX Bug Bounty

## Rubric (verbatim)

### Critical
- Significant loss or theft of user funds
- Large-scale insolvency of the protocol
- Permanent freezing of funds
- Unauthorized minting/printing of value

### High
- Network-level downtime or liveness failures (halting block production, crashing the chain, preventing settlement)
- Material degradation of the matching engine

### Medium
- Failures in non-core products (staking, governance) that do not result in fund loss but degrade UX or protocol guarantees

### Low
- Display, event-parsing, or Indexer-side issues that mislead users/clients but do not affect on-chain state or funds
"""

SPARK_SEVERITY_MD = """# Severity rubric - Spark Immunefi

### Critical (Blockchain/DLT)

| ID | Listed-impact sentence (verbatim) | Reward |
|---|---|---|
| CRIT-1 | Direct loss of funds | USD 100k |
| CRIT-2 | Permanent freezing of funds (fix requires hardfork) | USD 30k |

### High (Blockchain/DLT)

| ID | Listed-impact sentence (verbatim) | Reward |
|---|---|---|
| HIGH-1 | RPC API crash affecting projects with greater than or equal to 25% of the market capitalization on top of the respective layer (excluding DoS-related attack vector) | USD 25k |
"""

HYPERBRIDGE_SEVERITY_MD = """# Hyperbridge HackenProof

## Critical
Critical impact should be reserved for demonstrated in-scope behavior causing severe runtime, pallet, bridge, or smart-contract impact such as stealing or loss of funds, unauthorized transaction execution, transaction manipulation with severe impact, or bridge/message-proof logic failure enabling unauthorized asset movement.

## High
High impact covers serious in-scope incorrect behavior in the runtime, pallets, or smart contracts that can cause meaningful loss, unauthorized action, transaction manipulation, or severe logic failure but does not meet the Critical impact threshold.

## Medium
Medium impact covers demonstrated in-scope incorrect behavior with bounded impact, including logic errors, reentrancy/reordering issues, or arithmetic issues where the effect is real but less severe than High or Critical.

## Low
Low impact covers demonstrated minor in-scope incorrect behavior in runtime, pallet, or smart-contract logic.
"""


def _workspace(severity_md: Optional[str] = DYDX_SEVERITY_MD) -> Path:
    """Create a tmp workspace with optional SEVERITY.md."""
    root = Path(tempfile.mkdtemp(prefix="r63_test_"))
    (root / "submissions" / "paste_ready").mkdir(parents=True)
    if severity_md is not None:
        (root / "SEVERITY.md").write_text(severity_md, encoding="utf-8")
    return root


def _draft_in(ws: Path, body: str, filename: str = "finding-HIGH.md") -> Path:
    """Write a draft in submissions/paste_ready/."""
    p = ws / "submissions" / "paste_ready" / filename
    p.write_text(body, encoding="utf-8")
    return p


def _run(
    draft: Path,
    workspace: Optional[Path] = None,
    severity: Optional[str] = None,
    confidence_threshold: float = 0.3,
    max_tier_distance: int = 0,
    strict: bool = False,
) -> tuple[int, dict]:
    return mod.run(
        draft,
        workspace=workspace,
        severity_override=severity,
        confidence_threshold=confidence_threshold,
        max_tier_distance=max_tier_distance,
        strict=strict,
    )


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------
class TestNoSeverity(unittest.TestCase):
    def test_no_severity_passes_out_of_scope(self):
        """Draft with no severity header returns pass-out-of-scope."""
        ws = _workspace(DYDX_SEVERITY_MD)
        body = "# Finding\nSome description.\n\n## Impact\nFunds may be lost.\n"
        draft = _draft_in(ws, body, filename="finding-no-sev.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")


class TestRebuttal(unittest.TestCase):
    def test_rebuttal_html_comment_passes(self):
        ws = _workspace(DYDX_SEVERITY_MD)
        body = """# Finding-Critical

Severity: Critical

<!-- r63-rebuttal: operator confirmed impact via off-chain trace -->

## Impact

Display drift in Indexer.
"""
        draft = _draft_in(ws, body, filename="finding-rebuttal.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")
        self.assertIn("operator confirmed", payload["rebuttal"])

    def test_rebuttal_visible_line_passes(self):
        ws = _workspace(DYDX_SEVERITY_MD)
        body = """# Finding-High

Severity: High

r63-rebuttal: tier confirmed by program team

## Impact

A small display drift.
"""
        draft = _draft_in(ws, body, filename="finding-line-reb.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_oversized_rebuttal_ignored(self):
        ws = _workspace(DYDX_SEVERITY_MD)
        long_reason = "x" * 250
        body = f"""# Finding-Critical

Severity: Critical

<!-- r63-rebuttal: {long_reason} -->

## Impact

Display drift in Indexer.
"""
        draft = _draft_in(ws, body, filename="finding-bad-reb.md")
        rc, payload = _run(draft, workspace=ws)
        # Should NOT pass via rebuttal; original verdict (overclaim) wins.
        self.assertNotEqual(payload["verdict"], "ok-rebuttal")


class TestPassTierMatchesImpactSemantics(unittest.TestCase):
    def test_critical_with_fund_loss_passes(self):
        """A Critical claim that cites loss of funds passes."""
        ws = _workspace(DYDX_SEVERITY_MD)
        body = """# Finding-Critical

Severity: Critical

## Impact

Attacker can drain user funds from the protocol via a permission bypass.
Direct loss of user funds occurs when the attacker calls drainVault().
This results in theft of funds and protocol insolvency.
"""
        draft = _draft_in(ws, body, filename="finding-CRIT-good.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 0, f"verdict was {payload.get('verdict')} reason={payload.get('reason')}")
        self.assertEqual(payload["verdict"], "pass-tier-matches-impact-semantics")
        self.assertEqual(payload["evidence"]["top_tier_inferred"], "critical")

    def test_high_with_matching_engine_passes(self):
        ws = _workspace(DYDX_SEVERITY_MD)
        body = """# Finding-High

Severity: High

## Impact

Material degradation of the matching engine occurs when the attacker submits
N concurrent place-order messages. Network-level downtime is observed in our
PoC. Halting block production happens after T seconds.
"""
        draft = _draft_in(ws, body, filename="finding-HIGH-good.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 0, f"verdict was {payload.get('verdict')} reason={payload.get('reason')}")
        self.assertEqual(payload["verdict"], "pass-tier-matches-impact-semantics")

    def test_medium_with_staking_governance_passes(self):
        ws = _workspace(DYDX_SEVERITY_MD)
        body = """# Finding-Medium

Severity: Medium

## Impact

A logic error in the governance proposal lifecycle causes a vote tally
inconsistency. Non-core UX degradation; staking delegate accounting is
affected. Bounded impact.
"""
        draft = _draft_in(ws, body, filename="finding-MED-good.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 0, f"verdict was {payload.get('verdict')} reason={payload.get('reason')}")
        self.assertEqual(payload["verdict"], "pass-tier-matches-impact-semantics")

    def test_low_with_display_passes(self):
        ws = _workspace(DYDX_SEVERITY_MD)
        body = """# Finding-Low

Severity: Low

## Impact

Display drift in the Indexer where event-parsing misleads users. No
on-chain impact. SDK client-side validation gap.
"""
        draft = _draft_in(ws, body, filename="finding-LOW-good.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 0, f"verdict was {payload.get('verdict')} reason={payload.get('reason')}")
        self.assertEqual(payload["verdict"], "pass-tier-matches-impact-semantics")


class TestFailTierOverclaim(unittest.TestCase):
    def test_critical_with_display_impact_fails(self):
        """A draft claiming Critical but with display-class impact should fail-overclaim."""
        ws = _workspace(DYDX_SEVERITY_MD)
        body = """# Finding-OVERCLAIM

Severity: Critical

## Impact

Display drift in the Indexer where event-parsing misleads users about
order book state. No on-chain impact. SDK client-side validation gap.
This is misleading users.
"""
        draft = _draft_in(ws, body, filename="finding-overclaim.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-tier-overclaim")
        self.assertGreater(payload["evidence"]["tier_delta"], 0)

    def test_high_with_low_impact_fails(self):
        """High claim with Low impact => overclaim."""
        ws = _workspace(DYDX_SEVERITY_MD)
        body = """# Finding-High-Display

Severity: High

## Impact

Display drift in the Indexer. Event-parsing produces misleading output.
No on-chain impact. Indexer-side issue.
"""
        draft = _draft_in(ws, body, filename="finding-high-display.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-tier-overclaim")

    def test_cantina_213_anchor_overclaim(self):
        """Empirical anchor: cantina-213 in-process timing High vs localized pressure.

        Real-world cantina-213 had HIGH claim with in-process microbench evidence;
        triager closed as 'localized rate-limit pressure / bounded impact', i.e.
        the impact semantically matches MEDIUM (bounded, logic-error-class). The
        draft text below carries strong MEDIUM signal so the auto-tier scorer
        prefers MEDIUM. HIGH is then a 1-tier overclaim.

        r36-rebuttal: lane-RULE-63 registered in .auditooor/agent_pathspec.json
        """
        ws = _workspace(DYDX_SEVERITY_MD)
        body = """# Cantina-213 Anchor

Severity: High

## Impact

In-process microbenchmark shows 280ms vs 12ms baseline for a CheckTx-internal
timing path. Localized rate-limit pressure under load. The effect is a
bounded impact - localized; no matching-engine SLO breach is observed.
Rate-limiting issue with a logic error producing arithmetic overflow on a
bounded input set. Reentrancy is not involved; the path is reordering of
nested messages. Bounded loss in a non-core sub-path.
"""
        draft = _draft_in(ws, body, filename="finding-cantina-213.md")
        rc, payload = _run(draft, workspace=ws)
        # Anti-keywords should down-weight HIGH; impact should map to Medium
        # (rate-limit/bounded) so HIGH is an overclaim.
        self.assertEqual(rc, 1, f"got {payload.get('verdict')} {payload.get('reason')}")
        self.assertEqual(payload["verdict"], "fail-tier-overclaim")


class TestFailTierUnderclaimStrict(unittest.TestCase):
    def test_low_with_critical_impact_underclaim_strict(self):
        ws = _workspace(DYDX_SEVERITY_MD)
        body = """# Finding-Low-Theft

Severity: Low

## Impact

Attacker can steal user funds via direct loss of funds. Theft of funds is
demonstrated in PoC. Protocol insolvency results. Permanent freezing of
funds for the victim.
"""
        draft = _draft_in(ws, body, filename="finding-underclaim.md")
        rc, payload = _run(draft, workspace=ws, strict=True)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-tier-underclaim")

    def test_low_with_critical_impact_non_strict_passes(self):
        """Without --strict, under-claims pass."""
        ws = _workspace(DYDX_SEVERITY_MD)
        body = """# Finding-Low-Theft

Severity: Low

## Impact

Attacker can steal user funds via direct loss of funds. Theft of funds is
demonstrated in PoC. Protocol insolvency results.
"""
        draft = _draft_in(ws, body, filename="finding-underclaim2.md")
        rc, payload = _run(draft, workspace=ws, strict=False)
        # No --strict => under-claim is allowed.
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-tier-matches-impact-semantics")


class TestFailNoImpactSection(unittest.TestCase):
    def test_no_impact_section_fails(self):
        ws = _workspace(DYDX_SEVERITY_MD)
        body = """# Finding-No-Impact

Severity: Medium

## Summary

Some summary text here.

## Recommendation

Fix it.
"""
        draft = _draft_in(ws, body, filename="finding-no-impact.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-no-impact-section")


class TestNoSeverityMdInWorkspace(unittest.TestCase):
    def test_missing_severity_md_passes_out_of_scope(self):
        """When no SEVERITY.md is in the workspace, return pass-out-of-scope."""
        ws = _workspace(severity_md=None)
        body = """# Finding

Severity: Critical

## Impact

Attacker can drain funds.
"""
        draft = _draft_in(ws, body, filename="finding-no-sev-md.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")


class TestLowConfidence(unittest.TestCase):
    def test_low_confidence_passes_at_high_threshold(self):
        """A draft with weak impact text (one tier match) at high threshold
        returns pass-low-confidence."""
        ws = _workspace(DYDX_SEVERITY_MD)
        body = """# Finding

Severity: High

## Impact

Some bug; the fix is straightforward. We observed a single anomaly.
"""
        draft = _draft_in(ws, body, filename="finding-vague.md")
        # At a very high threshold, even a clear match becomes low-confidence.
        rc, payload = _run(draft, workspace=ws, confidence_threshold=0.99)
        # Either pass-low-confidence (preferred) or pass-tier-matches.
        self.assertIn(
            payload["verdict"],
            {"pass-low-confidence", "pass-tier-matches-impact-semantics"},
        )
        self.assertEqual(rc, 0)


class TestMaxTierDistance(unittest.TestCase):
    def test_max_distance_1_allows_one_tier_above(self):
        """With max_tier_distance=1, a one-tier-above claim is accepted."""
        ws = _workspace(DYDX_SEVERITY_MD)
        body = """# Finding-High-but-Medium-impact

Severity: High

## Impact

A logic error in the governance proposal lifecycle causes a vote tally
issue. Non-core UX degradation in staking delegate accounting. Bounded.
"""
        draft = _draft_in(ws, body, filename="finding-high-medium.md")
        rc, payload = _run(draft, workspace=ws, max_tier_distance=1)
        # With max_tier_distance=1, the High claim (1 above Medium) is fine.
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-tier-matches-impact-semantics")


class TestSparkAnchor(unittest.TestCase):
    def test_spark_critical_fund_loss_passes(self):
        ws = _workspace(SPARK_SEVERITY_MD)
        body = """# Spark coop-exit-bypass

Severity: Critical

## Impact

Direct loss of funds for the receiver in the Spark cooperative-exit flow.
Theft of funds occurs when the chain-watcher fails to detect the malicious
exit transaction. Permanent loss for the victim.
"""
        draft = _draft_in(ws, body, filename="spark-CRIT.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 0, f"reason: {payload.get('reason')}")
        self.assertEqual(payload["verdict"], "pass-tier-matches-impact-semantics")


class TestHyperbridgeAnchor(unittest.TestCase):
    def test_hyperbridge_medium_logic_error_passes(self):
        ws = _workspace(HYPERBRIDGE_SEVERITY_MD)
        body = """# HB pallet logic-error

Severity: Medium

## Impact

A logic error in the pallet causes a reentrancy issue with bounded impact.
Arithmetic underflow on a specific edge-case input. Real but less severe
than High or Critical.
"""
        draft = _draft_in(ws, body, filename="hb-pallet.md")
        rc, payload = _run(draft, workspace=ws)
        self.assertEqual(rc, 0, f"reason: {payload.get('reason')}")
        self.assertEqual(payload["verdict"], "pass-tier-matches-impact-semantics")


class TestEnvOverride(unittest.TestCase):
    def test_env_keywords_extend_tier(self):
        """AUDITOOOR_R63_TIER_KEYWORDS_HIGH adds extra keywords for HIGH."""
        ws = _workspace(DYDX_SEVERITY_MD)
        body = """# Finding-Custom

Severity: High

## Impact

XYZ_CUSTOM_HIGH_KEYWORD_TOKEN occurs in production. ABC_HIGH_SIGNAL_ONLY
is also present.
"""
        draft = _draft_in(ws, body, filename="finding-custom-env.md")
        os.environ["AUDITOOOR_R63_TIER_KEYWORDS_HIGH"] = (
            "xyz_custom_high_keyword_token\nabc_high_signal_only"
        )
        try:
            rc, payload = _run(draft, workspace=ws)
            self.assertEqual(rc, 0, f"reason: {payload.get('reason')}")
            self.assertEqual(payload["verdict"], "pass-tier-matches-impact-semantics")
        finally:
            del os.environ["AUDITOOOR_R63_TIER_KEYWORDS_HIGH"]


class TestSeverityMdParsing(unittest.TestCase):
    def test_parse_severity_md_tiers_extracts_dydx_keywords(self):
        out = mod.parse_severity_md_tiers(DYDX_SEVERITY_MD)
        # Critical should pick up fund-loss bullets.
        joined_crit = " ".join(out["critical"]).lower()
        self.assertIn("loss", joined_crit)
        # High should pick up matching engine.
        joined_high = " ".join(out["high"]).lower()
        self.assertIn("matching engine", joined_high)
        # Medium should mention staking/governance.
        joined_med = " ".join(out["medium"]).lower()
        self.assertIn("staking", joined_med)
        # Low should mention display.
        joined_low = " ".join(out["low"]).lower()
        self.assertIn("display", joined_low)

    def test_parse_severity_md_tiers_extracts_spark_table_rows(self):
        out = mod.parse_severity_md_tiers(SPARK_SEVERITY_MD)
        joined_crit = " ".join(out["critical"]).lower()
        self.assertIn("loss of funds", joined_crit)
        joined_high = " ".join(out["high"]).lower()
        self.assertIn("rpc api crash", joined_high)


class TestSchemaVersion(unittest.TestCase):
    def test_schema_constant(self):
        self.assertEqual(mod.SCHEMA_VERSION, "auditooor.r63_auto_tier_assignment.v1")

    def test_gate_constant(self):
        self.assertEqual(mod.GATE, "R63-AUTO-TIER-ASSIGNMENT")

    def test_tier_rank_complete(self):
        for tier in ["low", "medium", "high", "critical"]:
            self.assertIn(tier, mod.TIER_RANK)


if __name__ == "__main__":
    unittest.main()
