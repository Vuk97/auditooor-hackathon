"""Hermetic Cyfrin-style PDF fixture builder for W2.4 Cyfrin-variant tests.

Generates small synthetic PDFs that mimic the Cyfrin audit-report layout:
bracketed severity-coded finding IDs (``[C-1]`` / ``[H-1]`` / ``[M-1]`` /
``[L-1]`` / ``[I-1]`` / ``[G-1]``) followed by ``Description`` /
``Impact`` / ``Proof of Concept`` / ``Recommendation`` subsections, with
an optional ``Resolution: Fixed in commit <sha>`` / ``Status: Acknowledged``
trailer.

The point is to verify the Cyfrin parser against a structure we fully
control - real Cyfrin PDFs are pulled by the live driver only.

Spec ref: ``docs/HACKERMAN_AUDIT_FIRM_PDF_PREVIEW_2026-05-16.md`` (Cyfrin
section).

This module is invoked by the Cyfrin test suite on import to materialise
fixture PDFs into ``audit_firm_pdf_samples/cyfrin/`` if missing. It
depends on ``reportlab`` (already a Hackerman test dependency for
synthetic-corpus generation). All emitted PDFs carry the
``synthetic_fixture: true`` marker in the PDF metadata Keywords field so
downstream record consumers can assert hermetic-fixture provenance.

Kept separate from the ToB / Sherlock / Pashov / Zellic builders so the
firm-variant lanes evolve independently without merge pain.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, List


FIXTURE_DIR = Path(__file__).resolve().parent / "cyfrin"
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
    c.setProducer("auditooor-cyfrin-fixture-builder/1.0")
    c.setAuthor("auditooor-tests")
    c.setSubject("Cyfrin synthetic fixture (W2.4)")
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


def _sample_cyfrin_one_high() -> List[str]:
    """Single High finding with PoC + Resolution-Fixed-with-commit."""
    return [
        "Cyfrin",
        "Security Review: Sample Vault",
        "Date: 2024-09-01",
        "Auditors: Alice, Bob",
        "",
        "Executive Summary",
        "This is a synthetic Cyfrin-style audit report used for testing.",
        "",
        "Findings",
        "",
        "[H-1] Reentrancy in withdraw allows fund theft",
        "",
        "Description",
        "The withdraw function in contracts/Vault.sol:42 calls an external",
        "token before updating internal accounting state. An attacker can",
        "re-enter withdraw and drain the vault.",
        "",
        "Impact",
        "An attacker can withdraw arbitrary amounts of user funds via",
        "repeated re-entrant calls.",
        "",
        "Proof of Concept",
        "Alice deposits 100 tokens. Alice deploys a malicious token whose",
        "transfer hook calls back into withdraw before the balance update",
        "in contracts/Vault.sol:55. The re-entry drains the vault.",
        "",
        "Recommendation",
        "Apply the checks-effects-interactions pattern: update internal",
        "balances before the external token call.",
        "",
        "Resolution: Fixed in commit 1a2b3c4d5e6f7890abcdef1234567890abcdef12",
        "",
    ]


def _sample_cyfrin_one_of_each_severity() -> List[str]:
    """Six findings, one of each Cyfrin severity tier (C/H/M/L/I/G)."""
    return [
        "Cyfrin",
        "Security Review: Sample DEX",
        "",
        "[C-1] Missing access control on admin setter",
        "",
        "Description",
        "The setFeeRecipient function in contracts/DEX.sol:88 has no",
        "onlyOwner guard. Any caller can redirect the protocol fee stream.",
        "",
        "Impact",
        "Complete protocol fee revenue stream is redirected to attacker.",
        "",
        "Recommendation",
        "Add an onlyOwner modifier to setFeeRecipient.",
        "",
        "[H-1] Integer overflow in fee calculation",
        "",
        "Description",
        "The fee calc in contracts/DEX.sol:200 multiplies unchecked uints.",
        "",
        "Impact",
        "Large inputs trigger overflow leading to incorrect fee accounting.",
        "",
        "Recommendation",
        "Use Solidity 0.8+ checked arithmetic.",
        "",
        "[M-1] Incorrect event emission order",
        "",
        "Description",
        "Events in contracts/DEX.sol:300 emit before state is updated.",
        "",
        "Impact",
        "Off-chain indexers may capture an inconsistent state snapshot.",
        "",
        "Recommendation",
        "Move the emit to after the state update.",
        "",
        "[L-1] Missing zero-address check on token setter",
        "",
        "Description",
        "The setToken function in contracts/DEX.sol:400 lacks a zero check.",
        "",
        "Impact",
        "Misconfiguration could brick the contract.",
        "",
        "Recommendation",
        "Add require(newToken != address(0)) guard.",
        "",
        "[I-1] Inconsistent comment style across modules",
        "",
        "Description",
        "Comments in contracts/DEX.sol mix NatSpec and inline conventions.",
        "",
        "Impact",
        "Documentation generation tools may produce incomplete output.",
        "",
        "Recommendation",
        "Standardise on NatSpec for all public/external functions.",
        "",
        "[G-1] Cache storage reads in claim loop",
        "",
        "Description",
        "The claim loop in contracts/DEX.sol:500 re-reads storage per iter.",
        "",
        "Recommendation",
        "Cache the storage variable in a memory local before the loop.",
        "",
    ]


def _sample_cyfrin_acknowledged_no_commit() -> List[str]:
    """Finding with Resolution: Acknowledged (no commit ref)."""
    return [
        "Cyfrin",
        "Security Review: Sample Bridge",
        "",
        "[M-1] Centralisation risk in admin setter",
        "",
        "Description",
        "The setAdmin function in contracts/Bridge.sol:42 grants the new",
        "admin full control without a timelock.",
        "",
        "Impact",
        "A compromised admin key has immediate effect on the protocol.",
        "",
        "Recommendation",
        "Add a 48 hour timelock on admin transitions.",
        "",
        "Status: Acknowledged",
        "",
    ]


def _sample_cyfrin_informational_singleparagraph() -> List[str]:
    """Single Informational finding, single-paragraph body."""
    return [
        "Cyfrin",
        "Security Review: Sample Token",
        "",
        "[I-1] Minor gas-savings opportunity in transfer",
        "",
        "Description",
        "The transfer function in contracts/Token.sol:100 uses a redundant",
        "storage read that can be folded into the existing balance update.",
        "",
        "Recommendation",
        "Combine the balance read with the subsequent update.",
        "",
    ]


def _sample_cyfrin_gas_finding_no_impact() -> List[str]:
    """Gas finding (severity=G), no Impact section."""
    return [
        "Cyfrin",
        "Security Review: Sample AMM",
        "",
        "[G-1] Unnecessary SLOAD in swap path",
        "",
        "Description",
        "The swap function in contracts/AMM.sol:250 reads the reserves",
        "twice from storage on the hot path; cache locally for ~200 gas",
        "savings per swap.",
        "",
        "Recommendation",
        "Hoist the (reserve0, reserve1) read above the price check loop.",
        "",
    ]


def _sample_cyfrin_no_findings() -> List[str]:
    """Empty Cyfrin-style report (narrative text only, zero findings)."""
    return [
        "Cyfrin",
        "Security Review: Empty Sample",
        "",
        "Executive Summary",
        "No security findings were identified during this review.",
        "",
        "Project Overview",
        "This is intentionally empty fixture content for negative tests.",
        "",
    ]


_FIXTURES = {
    "cyfrin_one_high.pdf": _sample_cyfrin_one_high,
    "cyfrin_one_of_each_severity.pdf": _sample_cyfrin_one_of_each_severity,
    "cyfrin_acknowledged_no_commit.pdf": _sample_cyfrin_acknowledged_no_commit,
    "cyfrin_informational_singleparagraph.pdf": _sample_cyfrin_informational_singleparagraph,
    "cyfrin_gas_finding_no_impact.pdf": _sample_cyfrin_gas_finding_no_impact,
    "cyfrin_no_findings.pdf": _sample_cyfrin_no_findings,
}


def ensure_fixtures() -> dict:
    """Materialise the Cyfrin fixture PDFs on disk if missing; return path map."""
    out: dict = {}
    for filename, builder in _FIXTURES.items():
        target = FIXTURE_DIR / filename
        if not target.is_file():
            _build_pdf(target, builder())
        out[filename] = target
    return out
