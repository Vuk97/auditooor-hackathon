"""
Fixture-smoke detector for perp-autoclose-autohedge-missing-signature-check.

This row stays NOT_SUBMIT_READY. It proves only the owned source shape where a
public keeper-style auto-close/auto-hedge entrypoint accepts a position/vault
identifier plus caller-controlled settlement parameters, and the function body
does not visibly bind those settlement parameters to an owner signature check.
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


class PerpAutocloseAutohedgeMissingSignatureCheck(AbstractDetector):
    ARGUMENT = "perp-autoclose-autohedge-missing-signature-check"
    HELP = (
        "NOT_SUBMIT_READY fixture-smoke/source-shape proof only: keeper-style "
        "auto-close/auto-hedge entrypoint accepts caller-controlled settlement "
        "params without a visible owner signature check."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "perp-autoclose-autohedge-missing-signature-check.yaml"
    )
    WIKI_TITLE = (
        "Keeper auto-close / auto-hedge lets arbitrary caller pick settlement "
        "params without owner signature"
    )
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. This row "
        "flags only the owned auto-close/auto-hedge shape where a public "
        "keeper-style entrypoint accepts a position/vault id together with "
        "caller-controlled settlement parameters such as `swapData`, "
        "`settlementParams`, `path`, or slippage config, then closes or hedges "
        "the position without a visible EIP-712 / Permit / SignatureChecker / "
        "`ecrecover` validation inside that entrypoint."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A public `autoClose(positionId, params)` path becomes executable once "
        "a trigger condition is true. An attacker front-runs the keeper, "
        "passes attacker-chosen swap path and slippage fields in `params`, and "
        "the position closes through a pessimally routed market because the "
        "owner never signed those settlement choices. This row does not claim "
        "corpus-backed exploit evidence beyond the owned fixture pair."
    )
    WIKI_RECOMMENDATION = (
        "Require an owner-signed authorization that commits to the permitted "
        "settlement params, or constrain the keeper path to immutable owner-"
        "configured routes and slippage bounds. Keep this row "
        "NOT_SUBMIT_READY until corpus-backed evidence expands beyond fixture "
        "smoke."
    )

    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    _CONTRACT_GATE_RE = re.compile(
        r"\b(?:autoClose|autoHedge|triggerClose|triggerHedge|closePosition|"
        r"hedgePosition|Gamma|Perp|Vault)\b",
        re.IGNORECASE,
    )
    _ENTRY_NAME_RE = re.compile(
        r"^(?:autoClose|autoHedge|autoExit|triggerClose|triggerHedge|"
        r"rebalanceAndAutoHedge)$",
        re.IGNORECASE,
    )
    _ID_PARAM_RE = re.compile(
        r"function\s+\w+\s*\([^)]*\b(?:uint(?:256)?|bytes32)\s+"
        r"\w*(?:position|vault|account|subAccount|tokenId|id)\w*",
        re.IGNORECASE | re.DOTALL,
    )
    _SETTLEMENT_PARAM_RE = re.compile(
        r"function\s+\w+\s*\([^)]*\b(?:bytes|address\[\]|uint(?:256)?\[\]|"
        r"\w+(?:Params|Data|Route|Path))\b[^)]*"
        r"(?:settlement|swap|route|path|hedge|close)",
        re.IGNORECASE | re.DOTALL,
    )
    _SETTLEMENT_BODY_RE = re.compile(
        r"\b(?:settlementParams|swapParams|swapData|swapRoute|routeData|path|"
        r"closeParams|hedgeParams|slippageBps|minAmountOut|maxSlippage)\b",
        re.IGNORECASE,
    )
    _CLOSE_BODY_RE = re.compile(
        r"\b(?:closePosition|hedgePosition|_closePosition|_autoHedge|"
        r"_executeClose|_executeHedge|swapExact|exactInput|exactOutput)\b",
        re.IGNORECASE,
    )
    _SIGNATURE_RE = re.compile(
        r"\b(?:verifySignature|validateSignature|_validateOrder|permit2|"
        r"permitWitnessTransferFrom|SignatureChecker|isValidSignature|EIP712|"
        r"ecrecover|ECDSA\.recover|ownerSig|signature)\b",
        re.IGNORECASE,
    )
    _ONLY_OWNER_KEEPER_RE = re.compile(
        r"\b(?:onlyOwner|onlyAuthorizedKeeper|onlyKeeper|onlyRole\s*\(|"
        r"hasRole\s*\([^;]*(?:KEEPER|OPERATOR|EXECUTOR)|"
        r"msg\.sender\s*==\s*(?:owner|positionOwner|vaultOwner))",
        re.IGNORECASE,
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
        if not cls._ID_PARAM_RE.search(source):
            return False
        if not cls._SETTLEMENT_PARAM_RE.search(source):
            return False
        if not cls._SETTLEMENT_BODY_RE.search(source):
            return False
        if not cls._CLOSE_BODY_RE.search(source):
            return False
        if cls._SIGNATURE_RE.search(source):
            return False
        if cls._ONLY_OWNER_KEEPER_RE.search(source):
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
                    " -- perp-autoclose-autohedge-missing-signature-check: "
                    "public keeper-style auto-close/auto-hedge path accepts "
                    "caller-controlled settlement params without a visible "
                    "owner signature check. NOT_SUBMIT_READY: fixture-smoke/"
                    "source-shape proof only.",
                ]
                results.append(self.generate_result(info))
        return results
