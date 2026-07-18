"""
Fixture-smoke detector for permit-transfer-token-not-asserted-equal-expected.

This row remains NOT_SUBMIT_READY. It proves only the owned source shape where
an external/public entrypoint decodes a user-supplied Permit2
`PermitTransferFrom`, calls `permitTransferFrom(...)`, and credits an expected
asset path without asserting `permit.permitted.token == asset`.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract  # noqa: E402

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


def _source_of(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


class PermitTransferTokenNotAssertedEqualExpected(AbstractDetector):
    ARGUMENT = "permit-transfer-token-not-asserted-equal-expected"
    HELP = (
        "Permit2 `permitTransferFrom(...)` path consumes a decoded user permit "
        "without asserting `permit.permitted.token == expected asset`."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "permit-transfer-token-not-asserted-equal-expected.yaml"
    )
    WIKI_TITLE = "Permit2 repayment/deposit path omits token-equals-expected assertion"
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape proof only. The detector flags only the "
        "owned entrypoint shape where user-controlled Permit2 data is decoded "
        "into a `PermitTransferFrom`, consumed with "
        "`permitTransferFrom(...)`, and then used for an asset-crediting path "
        "without any assertion that `permit.permitted.token` equals the "
        "expected asset. NOT_SUBMIT_READY."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A repayment or liquidation path accepts opaque Permit2 data, decodes "
        "it, and pulls the signer-chosen token with "
        "`permitTransferFrom(...)`. If the function then credits debt "
        "repayment or deposit shares assuming the pulled asset was USDC, an "
        "attacker can sign a permit for a worthless token and receive credit "
        "as if they transferred the expected asset."
    )
    WIKI_RECOMMENDATION = (
        "Before calling `permitTransferFrom(...)`, assert that "
        "`permit.permitted.token` equals the exact asset the function expects. "
        "Do not promote this row from fixture smoke alone."
    )

    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    _CONTRACT_GATE_RE = re.compile(
        r"\b(?:permit2|ISignatureTransfer|PermitTransferFrom|SignatureTransferDetails)\b",
        re.IGNORECASE,
    )
    _ENTRY_NAME_RE = re.compile(
        r"^(?:repayWithPermit|depositWithPermit|liquidateWithPermit)$",
        re.IGNORECASE,
    )
    _OPAQUE_PERMIT_RE = re.compile(
        r"function\s+\w+\s*\([^)]*\bbytes(?:\s+calldata|\s+memory)?\s+\w*permit\w*",
        re.IGNORECASE | re.DOTALL,
    )
    _DECODE_RE = re.compile(
        r"abi\s*\.\s*decode\s*\([^;]*PermitTransferFrom",
        re.IGNORECASE | re.DOTALL,
    )
    _TRANSFER_RE = re.compile(
        r"\.\s*permitTransferFrom\s*\(",
        re.IGNORECASE | re.DOTALL,
    )
    _EXPECTED_ASSET_RE = re.compile(
        r"\b(?:asset|expectedToken|underlying|repayToken)\b",
        re.IGNORECASE,
    )
    _CREDIT_RE = re.compile(
        r"(?:_credit\w*|\brepay\w*|\bdebt\b|\bshares\b)",
        re.IGNORECASE,
    )
    _TOKEN_CHECK_RE = re.compile(
        r"permit\s*\.\s*permitted\s*\.\s*token\s*(?:==|!=)|"
        r"require\s*\([^;{}]*permit\s*\.\s*permitted\s*\.\s*token|"
        r"if\s*\([^;{}]*permit\s*\.\s*permitted\s*\.\s*token",
        re.IGNORECASE | re.DOTALL,
    )

    @classmethod
    def _function_matches(cls, function) -> bool:
        if getattr(function, "visibility", "") not in {"external", "public"}:
            return False
        if is_leaf_helper(function):
            return False

        name = getattr(function, "name", "") or ""
        if not cls._ENTRY_NAME_RE.match(name):
            return False

        source = _source_of(function)
        if not source:
            return False
        if not cls._OPAQUE_PERMIT_RE.search(source):
            return False
        if not cls._DECODE_RE.search(source):
            return False
        if not cls._TRANSFER_RE.search(source):
            return False
        if not cls._EXPECTED_ASSET_RE.search(source):
            return False
        if not cls._CREDIT_RE.search(source):
            return False
        if cls._TOKEN_CHECK_RE.search(source):
            return False
        return True

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue

            contract_source = _source_of(contract)
            if not contract_source:
                continue
            if not self._CONTRACT_GATE_RE.search(contract_source):
                continue

            for function in contract.functions_and_modifiers_declared:
                if not self._function_matches(function):
                    continue
                info = [
                    function,
                    " -- permit-transfer-token-not-asserted-equal-expected: "
                    "decoded Permit2 transfer path omits "
                    "`permit.permitted.token == expected asset`. "
                    "NOT_SUBMIT_READY: fixture-smoke/source-shape proof only.",
                ]
                results.append(self.generate_result(info))
        return results
