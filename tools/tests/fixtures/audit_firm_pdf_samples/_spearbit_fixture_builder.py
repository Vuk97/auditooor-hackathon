"""Hermetic Spearbit-style PDF fixture builder for W2.4 Spearbit-variant tests.

Generates small synthetic PDFs that mimic the Spearbit numbered-section
layout (``X.Y.Z Title`` headings + ``Severity: <Tier> Risk`` literal +
``Context`` / ``Impact`` / ``Recommendation`` / ``Resolution`` subsections).
The point is to verify the Spearbit parser against a structure we fully
control - real Spearbit PDFs are pulled by the live driver only.

Spec ref: ``docs/WAVE2_W24_PDF_DEEPMINE_SPEC_2026-05-16.md`` §5.x (Spearbit
variant).

Every PDF emitted by this builder carries ``synthetic_fixture`` in its
``Keywords`` metadata (reportlab ``setKeywords``) so downstream consumers
can audit-trail that the input was hermetic and not a real Spearbit blob.

Kept separate from ``_fixture_builder.py`` (Trail of Bits) /
``_pashov_fixture_builder.py`` / ``_sherlock_fixture_builder.py`` /
``_zellic_fixture_builder.py`` so concurrent sibling firm-variant lanes
can ship their own fixture builders without merge conflicts.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, List


FIXTURE_DIR = Path(__file__).resolve().parent / "spearbit"


def _build_pdf(out_path: Path, lines: Iterable[str]) -> None:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import LETTER

    out_path.parent.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(str(out_path), pagesize=LETTER)
    # Synthetic-fixture marker (Wave-2 W2.4 spec) - downstream auditors
    # can confirm the test fixture provenance via the PDF metadata.
    c.setTitle("Spearbit Synthetic Fixture")
    c.setAuthor("auditooor.tests.fixtures")
    c.setSubject("hermetic-synthetic-fixture")
    c.setKeywords("synthetic_fixture spearbit-style w24-deepmine")
    width, height = LETTER
    y = height - 72
    text_obj = c.beginText(72, y)
    text_obj.setFont("Helvetica", 11)
    for line in lines:
        if text_obj.getY() < 72:
            c.drawText(text_obj)
            c.showPage()
            text_obj = c.beginText(72, height - 72)
            text_obj.setFont("Helvetica", 11)
        text_obj.textLine(line)
    c.drawText(text_obj)
    c.showPage()
    c.save()


def _sample_spearbit_single_high() -> List[str]:
    return [
        "Spearbit Sample Audit Report",
        "Client: Sample DEX",
        "Lead auditor: someone@spearbit",
        "",
        "5.1.1 Reentrancy in withdraw allows fund theft",
        "",
        "Severity: High Risk",
        "",
        "Context",
        "The withdraw function in contracts/Vault.sol:42 calls an external",
        "token before updating internal accounting state. An attacker can",
        "re-enter withdraw and drain the vault.",
        "",
        "Impact",
        "An unprivileged user can drain the entire vault balance in a",
        "single transaction by triggering reentrant withdraws.",
        "",
        "Recommendation",
        "Apply the checks-effects-interactions pattern: update internal",
        "balances before the external token call.",
        "",
        "Resolution",
        "Fixed in commit abc12345.",
        "",
    ]


def _sample_spearbit_one_of_each_severity() -> List[str]:
    return [
        "Spearbit Sample Audit Report",
        "Client: Sample Lending",
        "",
        "5.1.1 Privileged setter accepts zero address",
        "",
        "Severity: Critical Risk",
        "",
        "Context",
        "setOwner in contracts/Owner.sol:10 lacks a zero-address guard.",
        "",
        "Impact",
        "Loss of contract ownership.",
        "",
        "Recommendation",
        "Add a require(_o != address(0)) check.",
        "",
        "Resolution",
        "Acknowledged.",
        "",
        "5.2.1 Reentrancy in withdraw allows fund theft",
        "",
        "Severity: High Risk",
        "",
        "Context",
        "withdraw in contracts/Vault.sol:42 calls token before updating.",
        "",
        "Impact",
        "Vault drain.",
        "",
        "Recommendation",
        "CEI pattern.",
        "",
        "5.3.1 Stale oracle price used for liquidation",
        "",
        "Severity: Medium Risk",
        "",
        "Context",
        "Liquidator reads oracle in contracts/Liq.sol:80 without timestamp",
        "freshness check.",
        "",
        "Impact",
        "Bad debt during stale-price windows.",
        "",
        "Recommendation",
        "Add staleness check.",
        "",
        "5.4.1 Missing event emission on parameter change",
        "",
        "Severity: Low Risk",
        "",
        "Context",
        "setParam in contracts/Config.sol:25 does not emit an event.",
        "",
        "Impact",
        "Reduced off-chain auditability.",
        "",
        "Recommendation",
        "Emit a ParamChanged event.",
        "",
        "5.5.1 Inconsistent NatSpec comment style",
        "",
        "Severity: Informational",
        "",
        "Context",
        "NatSpec comments in contracts/Token.sol:5 mix /// and /** */.",
        "",
        "Impact",
        "Code style only.",
        "",
        "Recommendation",
        "Standardise on one style.",
        "",
        "5.6.1 Cache storage reads in a local variable",
        "",
        "Severity: Gas Optimization",
        "",
        "Context",
        "Loop in contracts/Loop.sol:200 reads the same storage slot N times.",
        "",
        "Impact",
        "Higher gas cost.",
        "",
        "Recommendation",
        "Cache the storage slot in a local variable.",
        "",
    ]


def _sample_spearbit_resolution_disputed() -> List[str]:
    return [
        "Spearbit Sample Audit Report",
        "Client: Sample Bridge",
        "",
        "5.1.1 Bridge admin can sweep user deposits",
        "",
        "Severity: High Risk",
        "",
        "Context",
        "adminSweep in contracts/Bridge.sol:300 lets the admin pull any",
        "ERC20 from the bridge contract.",
        "",
        "Impact",
        "Trusted role can rug pull all bridge liquidity.",
        "",
        "Recommendation",
        "Restrict adminSweep to whitelisted tokens or remove the function.",
        "",
        "Resolution",
        "Disputed - the team considers admin trust the intended model.",
        "",
    ]


def _sample_spearbit_severity_extra_words() -> List[str]:
    return [
        "Spearbit Sample Audit Report",
        "Client: Sample Margin",
        "",
        "5.1.1 Liquidation incentive lets attacker self-liquidate at profit",
        "",
        "Severity: High Risk - exploitable in current parameter set",
        "",
        "Context",
        "liquidate in contracts/Margin.sol:155 grants a 10% incentive",
        "without checking the liquidator equals the position owner.",
        "",
        "Impact",
        "Self-liquidation arbitrage drains the insurance fund.",
        "",
        "Recommendation",
        "Reject self-liquidations.",
        "",
        "Resolution",
        "Acknowledged - patch tracked in PR #42.",
        "",
    ]


def _sample_spearbit_empty() -> List[str]:
    return [
        "Spearbit Sample Audit Report",
        "Client: Empty Sample",
        "",
        "Executive Summary",
        "No security findings were identified during this review.",
        "",
        "Project Overview",
        "This is intentionally empty fixture content for negative tests.",
        "",
    ]


def _sample_spearbit_malformed_no_section_headings() -> List[str]:
    return [
        "Spearbit Sample Audit Report",
        "Client: Malformed Sample",
        "",
        "This PDF contains paragraphs but no recognisable Spearbit X.Y.Z",
        "section headings. The parser must return zero findings.",
        "",
        "Some Sherlock-style header that should not match Spearbit:",
        "## H-1: Title that belongs to a different firm",
        "Severity: High",
        "Summary: Sherlock-shape finding, not Spearbit-shape.",
        "",
    ]


def _sample_spearbit_resolution_fixed_inline() -> List[str]:
    """Spearbit finding where Resolution contains a Fixed status keyword
    plus a commit reference (the common shape for landed audits)."""
    return [
        "Spearbit Sample Audit Report",
        "Client: Sample Staking",
        "",
        "5.1.1 Validator deregistration ignores staked balance",
        "",
        "Severity: Medium Risk",
        "",
        "Context",
        "deregister in contracts/Staking.sol:120 does not check the",
        "validator's outstanding stake.",
        "",
        "Impact",
        "Stake is locked in the contract permanently.",
        "",
        "Recommendation",
        "Refund the stake or block deregistration while staked.",
        "",
        "Resolution",
        "Fixed in commit deadbeef1234.",
        "",
    ]


def _sample_spearbit_mixed_with_sherlock_shape() -> List[str]:
    """One Spearbit-shape and one Sherlock-shape finding side-by-side.

    The Spearbit parser must catch ONLY the Spearbit-shape entry; the
    Sherlock-style ``## H-1:`` line should not match the Spearbit title
    regex.
    """
    return [
        "Spearbit Sample Audit Report",
        "Client: Mixed Sample",
        "",
        "5.1.1 Spearbit-shape finding wins parser pass",
        "",
        "Severity: Medium Risk",
        "",
        "Context",
        "Demonstrates the Spearbit X.Y.Z dotted section heading shape.",
        "",
        "Impact",
        "Captured by the Spearbit parser.",
        "",
        "Recommendation",
        "None - test fixture only.",
        "",
        "## H-1: Sherlock-shape decoy that should NOT match",
        "Severity: High",
        "Summary: This block should be invisible to the Spearbit parser.",
        "Recommendation: Ignored.",
        "",
    ]


_FIXTURES = {
    "spearbit_single_high.pdf": _sample_spearbit_single_high,
    "spearbit_one_of_each_severity.pdf": _sample_spearbit_one_of_each_severity,
    "spearbit_resolution_disputed.pdf": _sample_spearbit_resolution_disputed,
    "spearbit_severity_extra_words.pdf": _sample_spearbit_severity_extra_words,
    "spearbit_empty.pdf": _sample_spearbit_empty,
    "spearbit_malformed_no_section_headings.pdf": _sample_spearbit_malformed_no_section_headings,
    "spearbit_resolution_fixed_inline.pdf": _sample_spearbit_resolution_fixed_inline,
    "spearbit_mixed_with_sherlock_shape.pdf": _sample_spearbit_mixed_with_sherlock_shape,
}


def ensure_fixtures() -> dict:
    """Materialise the Spearbit fixture PDFs on disk if missing; return path map."""
    out: dict = {}
    for filename, builder in _FIXTURES.items():
        target = FIXTURE_DIR / filename
        if not target.is_file():
            _build_pdf(target, builder())
        out[filename] = target
    return out
