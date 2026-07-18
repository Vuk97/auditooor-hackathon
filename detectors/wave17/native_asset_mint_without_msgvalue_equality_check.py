"""
native-asset-mint-without-msgvalue-equality-check

Fixture-smoke/source-shape detector for the owned async-vault row where a
`requestDeposit(uint256 assets, ...)` style entrypoint accepts a native-token
path, wraps only `msg.value`, but records the user-declared `assets` into
deposit-request accounting without a visible `assets == msg.value` guard.

Submission posture: NOT_SUBMIT_READY. This is intentionally narrow and backed
only by the checked-in fixture pair.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


_CONTEXT_RE = re.compile(
    r"(?i)\b(?:pendingSilo|depositRequest|depositAssets|wrappedNativeToken|WETH|depositEth)\b"
)
_FUNCTION_NAME_RE = re.compile(r"(?i)^(?:requestDeposit|requestMint)$")
_NATIVE_BRANCH_RE = re.compile(
    r"(?is)\bif\s*\(\s*msg\.value\s*(?:!=\s*0|>\s*0)\s*\)"
)
_WRAP_CALL_RE = re.compile(
    r"(?is)\b(?:pendingSilo\s*\.\s*)?(?:depositEth|wrapNative|deposit)"
    r"\s*\{[^{};]*value\s*:\s*msg\.value[^{};]*\}\s*\("
)
_ACCOUNTING_WRITE_RE = re.compile(
    r"(?is)\b(?:depositRequest|depositAssets|totalDepositAssets|epochs)\b"
    r"[^;{}]*(?:\+=|=)\s*assets\b"
)
_EQUALITY_GUARD_RE = re.compile(
    r"(?is)\b(?:require|assert)\s*\(\s*(?:assets\s*==\s*msg\.value|msg\.value\s*==\s*assets)\b"
    r"|"
    r"\bif\s*\(\s*(?:assets\s*!=\s*msg\.value|msg\.value\s*!=\s*assets)\s*\)\s*revert\b"
)
_ASSETS_REBOUND_RE = re.compile(
    r"(?is)\bassets\s*=\s*(?:uint256\s*\(\s*)?msg\.value\b"
)


def _source(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _has_assets_param(function) -> bool:
    params = list(function.parameters or [])
    if not params:
        return False
    first = params[0]
    return (getattr(first, "name", "") or "") == "assets" and str(
        getattr(first, "type", "") or ""
    ) == "uint256"


class NativeAssetMintWithoutMsgvalueEqualityCheck(AbstractDetector):
    ARGUMENT = "native-asset-mint-without-msgvalue-equality-check"
    HELP = (
        "Async-vault requestDeposit-style native wrap path records `assets` "
        "into deposit-request accounting while wrapping only `msg.value`, "
        "without a visible `assets == msg.value` guard."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "native-asset-mint-without-msgvalue-equality-check.yaml"
    )
    WIKI_TITLE = "Vault mint with native-wrap path does not require assets == msg.value"
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape proof only: this row proves only the owned "
        "`requestDeposit(uint256 assets, ...)` shape where a native branch wraps "
        "`msg.value` into a pending silo while deposit-request accounting records "
        "the larger caller-declared `assets`. NOT_SUBMIT_READY."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A vault request path accepts `assets=10 ether` with `msg.value=1 wei`, "
        "calls `pendingSilo.depositEth{value: msg.value}(...)`, then writes "
        "`epochs[currentEpoch].depositRequest[controller] += assets;`. Later "
        "settlement can mint or reserve shares against the larger recorded assets "
        "than the native value actually received."
    )
    WIKI_RECOMMENDATION = (
        "Require `assets == msg.value` on the native wrap path or derive the "
        "accounted assets directly from `msg.value`. Do not promote this row "
        "from fixture smoke alone."
    )

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue

            contract_src = _source(contract)
            if not _CONTEXT_RE.search(contract_src):
                continue

            for function in contract.functions_and_modifiers_declared:
                if getattr(function, "visibility", "") not in {"external", "public"}:
                    continue
                if is_leaf_helper(function):
                    continue
                if not _FUNCTION_NAME_RE.search(function.name or ""):
                    continue
                if not _has_assets_param(function):
                    continue

                function_src = _source(function)
                if not function_src:
                    continue
                if not _NATIVE_BRANCH_RE.search(function_src):
                    continue
                if not _WRAP_CALL_RE.search(function_src):
                    continue
                if not _ACCOUNTING_WRITE_RE.search(function_src):
                    continue
                if _EQUALITY_GUARD_RE.search(function_src):
                    continue
                if _ASSETS_REBOUND_RE.search(function_src):
                    continue

                info = [
                    function,
                    (
                        " — native-asset-mint-without-msgvalue-equality-check: "
                        "native-wrap requestDeposit path records `assets` into "
                        "deposit-request accounting while wrapping only "
                        "`msg.value`. NOT_SUBMIT_READY: fixture-smoke/source-"
                        "shape proof only."
                    ),
                ]
                results.append(self.generate_result(info))
        return results
