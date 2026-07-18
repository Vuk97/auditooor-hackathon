"""Hermetic ToB-style PDF fixture builder for W2.4 Phase-1 tests.

We generate small synthetic PDFs that mimic the Trail of Bits NIST-style
layout (`<num>. <Title>` headings + `Severity: ...` / `Difficulty: ...`
labels + `Description` / `Recommendation` subsections). The point is to
verify the parser against a structure we fully control - real Trail of
Bits PDFs are pulled by the live driver only.

This module is invoked by the test suite on import to materialise the
fixture PDFs into the `audit_firm_pdf_samples/trailofbits/` directory if
they are missing. It depends on `reportlab` (already a Hackerman test
dependency for synthetic-corpus generation).
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, List


FIXTURE_DIR = Path(__file__).resolve().parent / "trailofbits"


def _build_pdf(out_path: Path, lines: Iterable[str]) -> None:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import LETTER

    out_path.parent.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(str(out_path), pagesize=LETTER)
    width, height = LETTER
    y = height - 72
    line_height = 14
    text_obj = c.beginText(72, y)
    text_obj.setFont("Helvetica", 11)
    for line in lines:
        # Page-break when y drops below 72.
        if text_obj.getY() < 72:
            c.drawText(text_obj)
            c.showPage()
            text_obj = c.beginText(72, height - 72)
            text_obj.setFont("Helvetica", 11)
        text_obj.textLine(line)
    c.drawText(text_obj)
    c.showPage()
    c.save()


def _sample_tob_two_findings() -> List[str]:
    return [
        "Trail of Bits Sample Audit Report",
        "Project: Sample Vault",
        "",
        "Executive Summary",
        "This is a synthetic Trail of Bits style report used for testing.",
        "",
        "1. Reentrancy in withdraw allows fund theft",
        "",
        "Severity: High",
        "Difficulty: Medium",
        "Type: Data Validation",
        "",
        "Description",
        "The withdraw function in target/contracts/Vault.sol:L42-L60 calls",
        "an external token before updating internal accounting state.",
        "An attacker can re-enter withdraw and drain the vault.",
        "",
        "Exploit Scenario",
        "Alice deposits and then re-enters withdraw via a malicious token.",
        "",
        "Recommendation",
        "Apply the checks-effects-interactions pattern: update internal",
        "balances before the external token call. Consider adding a",
        "non-reentrancy modifier to the withdraw function.",
        "",
        "2. Integer overflow in fee calculation results in loss",
        "",
        "Severity: Medium",
        "Difficulty: Low",
        "Type: Arithmetic",
        "",
        "Description",
        "The fee calculation in target/contracts/Fee.sol:L100 multiplies",
        "two unchecked uint256 values which can overflow for large inputs.",
        "",
        "Recommendation",
        "Use Solidity 0.8+ checked arithmetic or SafeMath for the fee",
        "calculation. Add unit tests covering the boundary cases.",
        "",
    ]


def _sample_tob_one_finding_with_long_term() -> List[str]:
    return [
        "Trail of Bits Sample Audit Report",
        "Project: Sample AMM",
        "",
        "1. Missing access control on admin setter",
        "",
        "Severity: Critical",
        "Difficulty: Low",
        "Type: Access Controls",
        "",
        "Description",
        "The setFeeRecipient function in target/contracts/AMM.sol:L88 has",
        "no onlyOwner guard. Any caller can redirect the protocol fee",
        "stream to an attacker-controlled address.",
        "",
        "Recommendation",
        "Add an onlyOwner modifier to setFeeRecipient. Confirm via tests.",
        "",
        "Long Term",
        "Adopt OpenZeppelin Ownable across all privileged setters and",
        "review the entire admin surface in a follow-up audit.",
        "",
    ]


def _sample_no_findings() -> List[str]:
    return [
        "Trail of Bits Sample Audit Report",
        "Project: Empty Sample",
        "",
        "Executive Summary",
        "No security findings were identified during this review.",
        "",
        "Project Overview",
        "This is intentionally empty fixture content for negative tests.",
        "",
    ]


def _sample_undetermined_severity() -> List[str]:
    return [
        "Trail of Bits Sample Audit Report",
        "Project: Sample Bridge",
        "",
        "1. Inconsistent error handling across deposit paths",
        "",
        "Severity: Undetermined",
        "Difficulty: Undetermined",
        "Type: Auditing and Logging",
        "",
        "Description",
        "The deposit paths in target/contracts/Bridge.sol:L20 and",
        "target/contracts/Bridge.sol:L75 use inconsistent error revert",
        "messages and event signatures.",
        "",
        "Recommendation",
        "Standardise error messages and event signatures across all",
        "deposit code paths.",
        "",
    ]


_FIXTURES = {
    "tob_two_findings.pdf": _sample_tob_two_findings,
    "tob_one_finding_long_term.pdf": _sample_tob_one_finding_with_long_term,
    "tob_no_findings.pdf": _sample_no_findings,
    "tob_undetermined_severity.pdf": _sample_undetermined_severity,
}


def ensure_fixtures() -> dict:
    """Materialise the fixture PDFs on disk if missing; return path map."""
    out: dict = {}
    for filename, builder in _FIXTURES.items():
        target = FIXTURE_DIR / filename
        if not target.is_file():
            _build_pdf(target, builder())
        out[filename] = target
    return out
