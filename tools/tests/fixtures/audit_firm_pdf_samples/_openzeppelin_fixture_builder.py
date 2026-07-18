"""Hermetic OpenZeppelin-style PDF fixture builder for W2.4 OZ-variant tests.

Generates small synthetic PDFs that mimic the OpenZeppelin audit-report layout:
bracketed severity-coded finding IDs (``[C-01]`` / ``[H-01]`` / ``[M-01]`` /
``[L-01]`` / ``[N-01]`` / ``[I-01]``) followed by ``Description`` /
``Recommendation`` / optional ``Mitigation`` / ``Resolution`` subsections.
Resolution lines reference PR# or commit SHAs (OZ canonical shape).

The point is to verify the OpenZeppelin parser against a structure we fully
control - real OpenZeppelin PDFs are pulled by the live driver only.

Spec ref: ``docs/WAVE2_W24_PDF_DEEPMINE_SPEC_2026-05-16.md`` (OpenZeppelin
section, PR-Wave2-B task brief).

This module is invoked by the OZ test suite on import to materialise
fixture PDFs into ``audit_firm_pdf_samples/openzeppelin/`` if missing. It
depends on ``reportlab`` (already a Hackerman test dependency). All
emitted PDFs carry the ``synthetic_fixture: true`` marker in the PDF
metadata Keywords field so downstream record consumers can assert
hermetic-fixture provenance.

Kept separate from the ToB / Sherlock / Pashov / Zellic / Cyfrin /
Spearbit builders so the firm-variant lanes evolve independently
without merge pain.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, List


FIXTURE_DIR = Path(__file__).resolve().parent / "openzeppelin"
SYNTHETIC_FIXTURE_KEYWORD = "synthetic_fixture:true"


def _build_pdf(out_path: Path, lines: Iterable[str]) -> None:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import LETTER

    out_path.parent.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(str(out_path), pagesize=LETTER)
    # Synthetic-fixture marker per task brief: every fixture PDF carries
    # ``synthetic_fixture:true`` in its Keywords metadata so the driver
    # can detect and surface hermetic provenance.
    c.setKeywords(SYNTHETIC_FIXTURE_KEYWORD)
    c.setProducer("auditooor-openzeppelin-fixture-builder/1.0")
    c.setAuthor("auditooor-tests")
    c.setSubject("OpenZeppelin synthetic fixture (W2.4)")
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


def _sample_oz_single_h01() -> List[str]:
    """Single H-01 finding with Resolution: Fixed in PR ref."""
    return [
        "OpenZeppelin",
        "Security Audit: Sample Protocol",
        "Date: 2024-09-15",
        "Audited by: Alice (lead), Bob, Carol",
        "",
        "Executive Summary",
        "This is a synthetic OpenZeppelin-style audit report used for testing.",
        "",
        "Findings",
        "",
        "[H-01] Reentrancy in withdraw enables fund theft",
        "",
        "Description",
        "The withdraw function in contracts/Vault.sol:42 transfers ERC-777",
        "tokens before updating internal accounting. An attacker re-enters",
        "withdraw via the token hook to drain the vault.",
        "",
        "Recommendation",
        "Apply the checks-effects-interactions pattern: update internal",
        "balances before the external token transfer, or add a nonReentrant",
        "guard from OpenZeppelin's ReentrancyGuard mixin.",
        "",
        "Resolution: Fixed in PR #1234",
        "",
    ]


def _sample_oz_one_of_each_severity() -> List[str]:
    """Six findings, one of each OZ severity tier (C/H/M/L/N/I)."""
    return [
        "OpenZeppelin",
        "Security Audit: Sample DEX",
        "",
        "[C-01] Missing access control on admin setter",
        "",
        "Description",
        "The setFeeRecipient function in contracts/DEX.sol:88 has no",
        "onlyOwner guard. Any caller can redirect the protocol fee stream.",
        "",
        "Recommendation",
        "Add an onlyOwner modifier to setFeeRecipient.",
        "",
        "[H-01] Integer overflow in fee calculation",
        "",
        "Description",
        "The fee calc in contracts/DEX.sol:200 multiplies unchecked uints.",
        "",
        "Recommendation",
        "Use Solidity 0.8+ checked arithmetic.",
        "",
        "[M-01] Incorrect event emission order",
        "",
        "Description",
        "Events in contracts/DEX.sol:300 emit before state is updated.",
        "",
        "Recommendation",
        "Move the emit to after the state update.",
        "",
        "[L-01] Missing zero-address check on token setter",
        "",
        "Description",
        "The setToken function in contracts/DEX.sol:400 lacks a zero check.",
        "",
        "Recommendation",
        "Add require(newToken != address(0)) guard.",
        "",
        "[N-01] Stylistic NatSpec inconsistency in interfaces",
        "",
        "Description",
        "Interface files in contracts/interfaces/ mix NatSpec conventions.",
        "",
        "Recommendation",
        "Standardise on the @notice / @dev / @param ordering.",
        "",
        "[I-01] Minor gas-savings opportunity in transfer",
        "",
        "Description",
        "The transfer function in contracts/Token.sol:100 uses a redundant",
        "storage read that can be folded into the existing balance update.",
        "",
        "Recommendation",
        "Combine the balance read with the subsequent update.",
        "",
    ]


def _sample_oz_resolution_acknowledged() -> List[str]:
    """Finding with Resolution: Acknowledged (no PR ref)."""
    return [
        "OpenZeppelin",
        "Security Audit: Sample Bridge",
        "",
        "[M-01] Centralisation risk in admin setter",
        "",
        "Description",
        "The setAdmin function in contracts/Bridge.sol:42 grants the new",
        "admin full control without a timelock.",
        "",
        "Recommendation",
        "Add a 48-hour timelock on admin transitions.",
        "",
        "Resolution: Acknowledged",
        "",
    ]


def _sample_oz_partially_fixed() -> List[str]:
    """Finding with Resolution: Partially Fixed and a PR ref."""
    return [
        "OpenZeppelin",
        "Security Audit: Sample Lending",
        "",
        "[H-01] Liquidation price oracle uses single-source feed",
        "",
        "Description",
        "The liquidation oracle in contracts/Liquidator.sol:120 reads",
        "from a single Chainlink feed without fallback or staleness checks.",
        "",
        "Recommendation",
        "Add a fallback oracle and a max-staleness guard.",
        "",
        "Resolution: Partially Fixed in PR #4321",
        "",
    ]


def _sample_oz_multi_digit_ids() -> List[str]:
    """Findings with H-10 and H-11 (validates 2-digit ID handling beyond H-09)."""
    return [
        "OpenZeppelin",
        "Security Audit: Sample Large Protocol",
        "",
        "[H-10] Improper handling of fee-on-transfer tokens",
        "",
        "Description",
        "The deposit path in contracts/Pool.sol:88 trusts the transfer",
        "amount parameter without re-checking the recipient balance.",
        "",
        "Recommendation",
        "Compute the delta of recipient balance before vs after transfer.",
        "",
        "Resolution: Fixed in PR #555",
        "",
        "[H-11] Insufficient slippage check on swap path",
        "",
        "Description",
        "The swap in contracts/Pool.sol:140 uses a hard-coded 100 bps slippage.",
        "",
        "Recommendation",
        "Accept user-supplied minOut and revert if final output is lower.",
        "",
        "Resolution: Acknowledged",
        "",
    ]


def _sample_oz_mitigation_label() -> List[str]:
    """Finding using Mitigation: instead of Resolution: as the trailer."""
    return [
        "OpenZeppelin",
        "Security Audit: Sample Staking",
        "",
        "[M-01] Reward calculation susceptible to dust accumulation",
        "",
        "Description",
        "The reward formula in contracts/Staking.sol:240 rounds down on",
        "each accrual, leaving dust amounts stranded in the contract.",
        "",
        "Recommendation",
        "Track residuals between accrual rounds and add them to the next",
        "distribution batch.",
        "",
        "Mitigation: Fixed in PR #888",
        "",
    ]


def _sample_oz_empty() -> List[str]:
    """Empty OZ-style report (narrative text only, zero findings)."""
    return [
        "OpenZeppelin",
        "Security Audit: Empty Sample",
        "",
        "Executive Summary",
        "No security findings were identified during this review.",
        "",
        "Project Overview",
        "This is intentionally empty fixture content for negative tests.",
        "",
    ]


def _sample_oz_malformed() -> List[str]:
    """Report-shaped text with no OZ bracketed prefix (no findings parse)."""
    return [
        "OpenZeppelin",
        "Security Audit: Malformed Sample",
        "",
        "Executive Summary",
        "Some narrative content here.",
        "",
        "Finding 1: This is not a bracketed-ID heading",
        "",
        "Description",
        "Even though there is body text here, the heading is not OZ-shaped",
        "so the extractor must return zero findings rather than mis-parsing.",
        "",
        "Recommendation",
        "Reject this content cleanly.",
        "",
    ]


def _sample_oz_note_tier() -> List[str]:
    """Single Note-tier (N-01) finding to verify the OZ-specific 'Note' tier."""
    return [
        "OpenZeppelin",
        "Security Audit: Sample Note Tier",
        "",
        "[N-01] Documentation gap on initialisation invariant",
        "",
        "Description",
        "The deployment script in scripts/deploy.ts does not document the",
        "invariant that initialize() must run in the same tx as the proxy",
        "deployment to prevent front-run takeover.",
        "",
        "Recommendation",
        "Add an explicit NatSpec block and a deploy-time assert.",
        "",
    ]


_FIXTURES = {
    "oz_single_h01.pdf": _sample_oz_single_h01,
    "oz_one_of_each_severity.pdf": _sample_oz_one_of_each_severity,
    "oz_resolution_acknowledged.pdf": _sample_oz_resolution_acknowledged,
    "oz_partially_fixed.pdf": _sample_oz_partially_fixed,
    "oz_multi_digit_ids.pdf": _sample_oz_multi_digit_ids,
    "oz_mitigation_label.pdf": _sample_oz_mitigation_label,
    "oz_empty.pdf": _sample_oz_empty,
    "oz_malformed_no_bracketed_prefix.pdf": _sample_oz_malformed,
    "oz_note_tier.pdf": _sample_oz_note_tier,
}


def ensure_fixtures() -> dict:
    """Materialise the OZ fixture PDFs on disk if missing; return path map."""
    out: dict = {}
    for filename, builder in _FIXTURES.items():
        target = FIXTURE_DIR / filename
        if not target.is_file():
            _build_pdf(target, builder())
        out[filename] = target
    return out
