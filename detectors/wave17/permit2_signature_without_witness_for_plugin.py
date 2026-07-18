"""
Fixture-smoke detector for permit2-signature-without-witness-for-plugin.

This is intentionally narrow and stays NOT_SUBMIT_READY. It proves only the
owned source shape where a public proxy/router entrypoint:
1. consumes a plain Permit2 `permit(...)`,
2. performs a plain Permit2 `transferFrom(...)`,
3. then delegatecalls into a plugin/target using user-supplied calldata,
4. without using a witness-bound Permit2 path.
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


class Permit2SignatureWithoutWitnessForPlugin(AbstractDetector):
    ARGUMENT = "permit2-signature-without-witness-for-plugin"
    HELP = (
        "Proxy/router consumes plain Permit2 permit + transferFrom before "
        "delegatecalling into a plugin/target, without witness binding."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "permit2-signature-without-witness-for-plugin.yaml"
    )
    WIKI_TITLE = "Permit2 permit + transferFrom delegates to plugin without witness binding"
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape proof only. The detector flags only the "
        "owned proxy/router shape where a public entrypoint first consumes "
        "Permit2 via plain `permit(...)`, then uses plain `transferFrom(...)`, "
        "and then `delegatecall`s into a plugin/target using calldata supplied "
        "by the caller. The checked shape does not use "
        "`permitWitnessTransferFrom`, so the delegated intent is not bound into "
        "the signature. NOT_SUBMIT_READY."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A user signs a Permit2 `PermitSingle` for a proxy. The proxy consumes "
        "the signature, pulls tokens with `transferFrom`, and then "
        "`delegatecall`s into a plugin chosen by the user. A malicious plugin "
        "can spend the proxy-held authority for its own transfer path because "
        "the signature never committed to the delegated target or calldata."
    )
    WIKI_RECOMMENDATION = (
        "Bind the delegated intent with `permitWitnessTransferFrom` or perform "
        "the token pull inside the same tightly-scoped action that consumes the "
        "user intent. Do not promote this row from fixture smoke alone."
    )

    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    _CONTRACT_GATE_RE = re.compile(
        r"\b(?:PermitSingle|permit2|IAllowanceTransfer|ISignatureTransfer)\b",
        re.IGNORECASE,
    )
    _ENTRY_NAME_RE = re.compile(
        r"^(?:execute|executeWithPermit|routeWithPermit|forwardWithPermit)$",
        re.IGNORECASE,
    )
    _SIG_BYTES_PARAM_RE = re.compile(
        r"function\s+\w+\s*\([^)]*\bbytes(?:\s+calldata|\s+memory)?\s+\w*(?:sig|signature|permit|data)\w*",
        re.IGNORECASE | re.DOTALL,
    )
    _TARGET_PARAM_RE = re.compile(
        r"function\s+\w+\s*\([^)]*\baddress\s+\w*(?:plugin|target)\w*",
        re.IGNORECASE | re.DOTALL,
    )
    _PLAIN_PERMIT_RE = re.compile(
        r"\.\s*permit\s*\([^;]*\bPermitSingle\b|"
        r"\.\s*permit\s*\([^;]*\bpermitSingle\b",
        re.IGNORECASE | re.DOTALL,
    )
    _PLAIN_TRANSFER_RE = re.compile(
        r"\.\s*transferFrom\s*\([^;]*\b(?:AllowanceTransfer|TokenPermissions|details|owner|from)\b",
        re.IGNORECASE | re.DOTALL,
    )
    _DELEGATECALL_RE = re.compile(
        r"\b(?:plugin|target)\b[^;{}]*\.delegatecall\s*\(",
        re.IGNORECASE | re.DOTALL,
    )
    _WITNESS_RE = re.compile(r"permitWitnessTransferFrom|witness", re.IGNORECASE)
    _TRUSTED_TARGET_RE = re.compile(
        r"\b(?:immutable|constant)\b[^;\n]*\b(?:plugin|target)\b|"
        r"\b(?:plugin|target)\b[^;\n]*\b(?:immutable|constant)\b",
        re.IGNORECASE,
    )

    @classmethod
    def _function_matches(cls, function) -> bool:
        if getattr(function, "visibility", "") not in {"external", "public"}:
            return False
        if is_leaf_helper(function):
            return False

        name = getattr(function, "name", "") or ""
        source = _source_of(function)
        if not source:
            return False
        if not cls._ENTRY_NAME_RE.match(name):
            return False
        if not cls._SIG_BYTES_PARAM_RE.search(source):
            return False
        if not cls._TARGET_PARAM_RE.search(source):
            return False
        if not cls._PLAIN_PERMIT_RE.search(source):
            return False
        if not cls._PLAIN_TRANSFER_RE.search(source):
            return False
        if not cls._DELEGATECALL_RE.search(source):
            return False
        if cls._WITNESS_RE.search(source):
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
            if self._TRUSTED_TARGET_RE.search(contract_source):
                continue

            for function in contract.functions_and_modifiers_declared:
                if not self._function_matches(function):
                    continue
                info = [
                    function,
                    " -- permit2-signature-without-witness-for-plugin: public "
                    "Permit2 `permit` + `transferFrom` path delegatecalls into "
                    "a plugin/target without witness binding. "
                    "NOT_SUBMIT_READY: fixture-smoke/source-shape proof only.",
                ]
                results.append(self.generate_result(info))
        return results
