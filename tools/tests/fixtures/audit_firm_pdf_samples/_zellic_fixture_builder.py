"""Hermetic Zellic-style PDF fixture builder for W2.4 Zellic-variant tests.

Generates small synthetic PDFs that mimic the Zellic numbered-finding-
table layout (``Finding N: <Title>`` headings + ``Severity:`` /
``Impact:`` / ``Likelihood:`` labels + ``Description`` / ``Recommendation``
subsections). The point is to verify the Zellic parser against a
structure we fully control - real Zellic PDFs are pulled by the live
driver only.

Spec ref: ``docs/WAVE2_W24_PDF_DEEPMINE_SPEC_2026-05-16.md`` §5.2.

This module is invoked by the Zellic test suite on import to materialise
fixture PDFs into ``audit_firm_pdf_samples/zellic/`` if missing. It
depends on ``reportlab`` (already a Hackerman test dependency for
synthetic-corpus generation).

Kept separate from ``_fixture_builder.py`` (Trail of Bits) so concurrent
sibling firm-variant lanes (Pashov, Sherlock, etc.) can ship their own
fixture builders without merge conflicts.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, List


FIXTURE_DIR = Path(__file__).resolve().parent / "zellic"


def _build_pdf(out_path: Path, lines: Iterable[str]) -> None:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import LETTER

    out_path.parent.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(str(out_path), pagesize=LETTER)
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


def _sample_zellic_two_findings() -> List[str]:
    return [
        "Zellic Sample Audit Report",
        "Project: Sample DEX",
        "",
        "Executive Summary",
        "This is a synthetic Zellic style report used for testing.",
        "",
        "Findings",
        "",
        "Finding 1: Reentrancy in withdraw allows fund theft",
        "",
        "Severity: High",
        "Impact: High",
        "Likelihood: Medium",
        "",
        "Description",
        "The withdraw function in contracts/Vault.sol:42 calls an external",
        "token before updating internal accounting state. An attacker can",
        "re-enter withdraw and drain the vault.",
        "",
        "Recommendation",
        "Apply the checks-effects-interactions pattern: update internal",
        "balances before the external token call. Add a non-reentrancy",
        "modifier to the withdraw function.",
        "",
        "Finding 2: Integer overflow in fee calculation results in loss",
        "",
        "Severity: Medium",
        "Impact: Medium",
        "Likelihood: Low",
        "",
        "Description",
        "The fee calculation in contracts/Fee.sol:100 multiplies two",
        "unchecked uint256 values which can overflow for large inputs.",
        "",
        "Recommendation",
        "Use Solidity 0.8+ checked arithmetic or SafeMath for the fee",
        "calculation. Add unit tests covering the boundary cases.",
        "",
    ]


def _sample_zellic_one_finding_hash_id() -> List[str]:
    """Zellic-style report using ``Finding #N:`` heading variant."""
    return [
        "Zellic Sample Audit Report",
        "Project: Sample Bridge",
        "",
        "Finding #1: Missing access control on admin setter",
        "",
        "Severity: Critical",
        "Impact: Critical",
        "Likelihood: High",
        "",
        "Description",
        "The setFeeRecipient function in contracts/Bridge.sol:88 has no",
        "onlyOwner guard. Any caller can redirect the protocol fee stream",
        "to an attacker-controlled address.",
        "",
        "Recommendation",
        "Add an onlyOwner modifier to setFeeRecipient. Confirm via tests.",
        "",
        "References",
        "https://example.org/zellic/2024-bridge-audit",
        "",
    ]


def _sample_zellic_no_findings() -> List[str]:
    return [
        "Zellic Sample Audit Report",
        "Project: Empty Sample",
        "",
        "Executive Summary",
        "No security findings were identified during this review.",
        "",
        "Project Overview",
        "This is intentionally empty fixture content for negative tests.",
        "",
    ]


def _sample_zellic_informational_severity() -> List[str]:
    return [
        "Zellic Sample Audit Report",
        "Project: Sample Lending",
        "",
        "Finding 1: Inconsistent event emission across deposit paths",
        "",
        "Severity: Informational",
        "Impact: None",
        "Likelihood: None",
        "",
        "Description",
        "The deposit paths in contracts/Lending.sol:20 and",
        "contracts/Lending.sol:75 emit inconsistent event signatures.",
        "",
        "Recommendation",
        "Standardise event signatures across all deposit code paths.",
        "",
    ]


_FIXTURES = {
    "zellic_two_findings.pdf": _sample_zellic_two_findings,
    "zellic_one_finding_hash_id.pdf": _sample_zellic_one_finding_hash_id,
    "zellic_no_findings.pdf": _sample_zellic_no_findings,
    "zellic_informational_severity.pdf": _sample_zellic_informational_severity,
}


def ensure_fixtures() -> dict:
    """Materialise the Zellic fixture PDFs on disk if missing; return path map."""
    out: dict = {}
    for filename, builder in _FIXTURES.items():
        target = FIXTURE_DIR / filename
        if not target.is_file():
            _build_pdf(target, builder())
        out[filename] = target
    return out
