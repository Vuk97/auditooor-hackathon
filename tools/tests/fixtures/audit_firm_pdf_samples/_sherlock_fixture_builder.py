"""Hermetic Sherlock-style PDF fixture builder for W2.4 Phase-1 tests.

Generates small synthetic PDFs that mimic the Sherlock contest-result
layout (``## <Letter>-<Num>: <Title>`` headings + ``Source:`` /
``Severity:`` / ``Summary:`` / ``Recommendation:`` / ``Resolution:``
fields). The point is to verify the parser against a structure we
fully control - real Sherlock PDFs are pulled by the live driver only.

This module is invoked by the test suite on import to materialise the
fixture PDFs into ``audit_firm_pdf_samples/sherlock/`` if they are
missing. It depends on ``reportlab`` (already a Hackerman test
dependency for synthetic-corpus generation).

Kept separate from ``_fixture_builder.py`` (the ToB builder) so the two
parser variants can evolve independently without merge-pain.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, List


FIXTURE_DIR = Path(__file__).resolve().parent / "sherlock"


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
        if text_obj.getY() < 72:
            c.drawText(text_obj)
            c.showPage()
            text_obj = c.beginText(72, height - 72)
            text_obj.setFont("Helvetica", 11)
        text_obj.textLine(line)
    c.drawText(text_obj)
    c.showPage()
    c.save()


def _sample_sherlock_two_findings_high_medium() -> List[str]:
    return [
        "Sherlock Audit Report",
        "Project: Sample Vault",
        "Date: 2024-03-15",
        "",
        "Executive Summary",
        "This is a synthetic Sherlock-style contest report used for testing.",
        "",
        "## H-1: Reentrancy in withdraw allows fund theft",
        "",
        "Source: https://github.com/sample/vault/blob/main/contracts/Vault.sol#L42-L60",
        "Severity: High",
        "",
        "Summary: The withdraw function in target/contracts/Vault.sol:L42-L60",
        "calls an external token before updating internal accounting state.",
        "An attacker can re-enter withdraw and drain the vault.",
        "",
        "Recommendation: Apply the checks-effects-interactions pattern: update",
        "internal balances before the external token call. Consider adding a",
        "non-reentrancy modifier to the withdraw function.",
        "",
        "Resolution: Fixed in commit deadbeefcafebabe1234. The team added the",
        "nonReentrant modifier and reordered the state update.",
        "",
        "## M-2: Integer overflow in fee calculation results in loss",
        "",
        "Source: target/contracts/Fee.sol:L100",
        "Severity: Medium",
        "",
        "Summary: The fee calculation in target/contracts/Fee.sol:L100 multiplies",
        "two unchecked uint256 values which can overflow for large inputs.",
        "",
        "Recommendation: Use Solidity 0.8+ checked arithmetic or SafeMath for the",
        "fee calculation. Add unit tests covering the boundary cases.",
        "",
        "Resolution: Acknowledged. The team will address in the next release.",
        "",
    ]


def _sample_sherlock_critical_with_inline_summary() -> List[str]:
    return [
        "Sherlock Audit Report",
        "Project: Sample AMM",
        "",
        "## C-1: Missing access control on admin setter",
        "",
        "Source: https://github.com/sample/amm/blob/main/contracts/AMM.sol#L88",
        "Severity: Critical",
        "Summary: The setFeeRecipient function in target/contracts/AMM.sol:L88 has",
        "no onlyOwner guard. Any caller can redirect the protocol fee",
        "stream to an attacker-controlled address.",
        "",
        "Recommendation: Add an onlyOwner modifier to setFeeRecipient. Confirm via",
        "tests covering the privileged-caller and non-privileged-caller paths.",
        "",
        "Resolution: Fixed in PR #42; commit cafe1234.",
        "",
    ]


def _sample_sherlock_no_findings() -> List[str]:
    return [
        "Sherlock Audit Report",
        "Project: Empty Sample",
        "",
        "Executive Summary",
        "No security findings were identified during this review. The team",
        "delivered a clean codebase with strong test coverage and idiomatic",
        "design patterns throughout.",
        "",
        "Project Overview",
        "This is intentionally empty fixture content for negative tests.",
        "",
    ]


def _sample_sherlock_low_without_severity_field() -> List[str]:
    """Letter-only severity (no ``Severity:`` body field).

    Exercises the fallback path where the parser must infer severity from
    the heading letter. Some Sherlock PDFs render contest pages without
    the explicit ``Severity:`` row when the contest template was an
    older revision.
    """
    return [
        "Sherlock Audit Report",
        "Project: Sample Bridge",
        "",
        "## L-3: Inconsistent error handling across deposit paths",
        "",
        "Source: target/contracts/Bridge.sol:L20",
        "",
        "Summary: The deposit paths in target/contracts/Bridge.sol:L20 and",
        "target/contracts/Bridge.sol:L75 use inconsistent error revert messages",
        "and event signatures, making off-chain monitoring fragile.",
        "",
        "Recommendation: Standardise error messages and event signatures across",
        "all deposit code paths. Document the canonical shape in CONTRIBUTING.md.",
        "",
        "Resolution: Acknowledged.",
        "",
    ]


_FIXTURES = {
    "sherlock_two_findings.pdf": _sample_sherlock_two_findings_high_medium,
    "sherlock_critical_inline_summary.pdf": _sample_sherlock_critical_with_inline_summary,
    "sherlock_no_findings.pdf": _sample_sherlock_no_findings,
    "sherlock_low_letter_only_severity.pdf": _sample_sherlock_low_without_severity_field,
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
