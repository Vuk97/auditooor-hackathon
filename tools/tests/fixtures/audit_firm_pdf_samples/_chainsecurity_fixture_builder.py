"""Hermetic ChainSecurity-style PDF fixture builder for W2.4 tests.

Generates small synthetic PDFs that mimic the ChainSecurity audit-report
layout: bracketed sequential finding IDs (``[CS-1]`` / ``[CS-2]`` / ...)
with a separate severity label line followed by ``Description`` /
``Acceptance Criteria`` / ``Recommendation`` / ``Acknowledgement``
subsections.

ChainSecurity-specific shapes:
  - Sequential ``[CS-N]`` IDs (no severity letter prefix).
  - Severity rendered as a bare label (Critical/High/Medium/Low/
    Informational/Best Practice) on its own line near the title.
  - ``Acceptance Criteria`` subsection (unique to ChainSecurity).
  - ``Acknowledgement`` section carrying verbatim resolution wording
    such as ``Code Corrected`` / ``Acknowledged`` / ``Risk Accepted``.

The point is to verify the ChainSecurity parser against a structure we
fully control - real ChainSecurity PDFs are pulled by the live driver
only.

Spec ref: ``docs/WAVE2_W24_PDF_DEEPMINE_SPEC_2026-05-16.md``
(ChainSecurity section).

Kept separate from the ToB / Sherlock / Pashov / Zellic / Cyfrin /
Spearbit builders so the firm-variant lanes evolve independently
without merge pain.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, List


FIXTURE_DIR = Path(__file__).resolve().parent / "chainsecurity"
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
    c.setProducer("auditooor-chainsecurity-fixture-builder/1.0")
    c.setAuthor("auditooor-tests")
    c.setSubject("ChainSecurity synthetic fixture (W2.4)")
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


def _sample_chainsec_one_high() -> List[str]:
    """Single CS-1 High finding with Acceptance Criteria + Acknowledgement."""
    return [
        "ChainSecurity",
        "Security Audit Report",
        "Protocol Audited: Sample Lending",
        "Date: 2024-08-15",
        "Auditors: Alice, Bob",
        "Version: 1.0",
        "",
        "Findings",
        "",
        "[CS-1] Reentrancy in withdraw allows fund theft",
        "",
        "High",
        "",
        "Description",
        "The withdraw function in contracts/Lending.sol:88 calls an",
        "external token before updating internal accounting. An attacker",
        "can re-enter withdraw and drain the protocol.",
        "",
        "Acceptance Criteria",
        "The withdraw path must update internal balances strictly before",
        "performing any external token transfer. No re-entrant call may",
        "observe a stale balance.",
        "",
        "Recommendation",
        "Apply the checks-effects-interactions pattern: update internal",
        "balances before the external token call. Consider adding a",
        "reentrancy guard modifier for defence in depth.",
        "",
        "Acknowledgement",
        "Code Corrected",
        "The team applied the recommended pattern in the follow-up commit.",
        "",
    ]


def _sample_chainsec_multi_severity() -> List[str]:
    """Multi-finding: CS-1 Critical, CS-2 High, CS-3 Medium, CS-4 Low, CS-5 Informational."""
    return [
        "ChainSecurity",
        "Security Audit Report: Sample DEX",
        "",
        "[CS-1] Missing access control on admin setter",
        "",
        "Critical",
        "",
        "Description",
        "The setFeeRecipient function in contracts/DEX.sol:42 has no",
        "onlyOwner guard. Any caller can redirect the protocol fee.",
        "",
        "Recommendation",
        "Add an onlyOwner modifier to setFeeRecipient.",
        "",
        "Acknowledgement",
        "Code Corrected",
        "",
        "[CS-2] Integer overflow in fee calculation",
        "",
        "High",
        "",
        "Description",
        "The fee calc in contracts/DEX.sol:200 multiplies unchecked uints.",
        "",
        "Recommendation",
        "Use Solidity 0.8+ checked arithmetic.",
        "",
        "Acknowledgement",
        "Code Corrected",
        "",
        "[CS-3] Incorrect event emission order",
        "",
        "Medium",
        "",
        "Description",
        "Events in contracts/DEX.sol:300 emit before state is updated.",
        "",
        "Recommendation",
        "Move the emit to after the state update.",
        "",
        "Acknowledgement",
        "Acknowledged",
        "",
        "[CS-4] Missing zero-address check on token setter",
        "",
        "Low",
        "",
        "Description",
        "The setToken function in contracts/DEX.sol:400 lacks a zero check.",
        "",
        "Recommendation",
        "Add require(newToken != address(0)) guard.",
        "",
        "Acknowledgement",
        "Risk Accepted",
        "The team prefers to keep the function unconstrained for upgrade flexibility.",
        "",
        "[CS-5] Inconsistent comment style across modules",
        "",
        "Informational",
        "",
        "Description",
        "Comments in contracts/DEX.sol mix NatSpec and inline conventions.",
        "",
        "Recommendation",
        "Standardise on NatSpec for all public/external functions.",
        "",
        "Acknowledgement",
        "Acknowledged",
        "",
    ]


def _sample_chainsec_risk_accepted() -> List[str]:
    """Finding with Risk Accepted resolution."""
    return [
        "ChainSecurity",
        "Security Audit Report: Sample Bridge",
        "",
        "[CS-1] Centralisation risk in admin transition",
        "",
        "Medium",
        "",
        "Description",
        "The setAdmin function in contracts/Bridge.sol:64 grants the new",
        "admin full control without a timelock.",
        "",
        "Acceptance Criteria",
        "Administrative transitions must be delayed by at least 48 hours.",
        "",
        "Recommendation",
        "Add a 48 hour timelock on admin transitions.",
        "",
        "Acknowledgement",
        "Risk Accepted",
        "The team has accepted this risk and will mitigate operationally.",
        "",
    ]


def _sample_chainsec_best_practice() -> List[str]:
    """Single finding tagged with the ChainSecurity-specific Best Practice tier."""
    return [
        "ChainSecurity",
        "Security Audit Report: Sample Token",
        "",
        "[CS-1] Use of magic number in transfer limit",
        "",
        "Best Practice",
        "",
        "Description",
        "The transfer function in contracts/Token.sol:120 hardcodes the",
        "transfer cap as a literal rather than a named constant.",
        "",
        "Recommendation",
        "Define a named constant TRANSFER_CAP_LIMIT and reference it.",
        "",
        "Acknowledgement",
        "Acknowledged",
        "",
    ]


def _sample_chainsec_no_findings() -> List[str]:
    """Empty ChainSecurity-style report (no findings)."""
    return [
        "ChainSecurity",
        "Security Audit Report: Empty Sample",
        "",
        "Executive Summary",
        "No security findings were identified during this review.",
        "",
        "Project Overview",
        "This is intentionally empty fixture content for negative tests.",
        "",
    ]


_FIXTURES = {
    "chainsec_one_high.pdf": _sample_chainsec_one_high,
    "chainsec_multi_severity.pdf": _sample_chainsec_multi_severity,
    "chainsec_risk_accepted.pdf": _sample_chainsec_risk_accepted,
    "chainsec_best_practice.pdf": _sample_chainsec_best_practice,
    "chainsec_no_findings.pdf": _sample_chainsec_no_findings,
}


def ensure_fixtures() -> dict:
    """Materialise the ChainSecurity fixture PDFs on disk if missing; return path map."""
    out: dict = {}
    for filename, builder in _FIXTURES.items():
        target = FIXTURE_DIR / filename
        if not target.is_file():
            _build_pdf(target, builder())
        out[filename] = target
    return out
