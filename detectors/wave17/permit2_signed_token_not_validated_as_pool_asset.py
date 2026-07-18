"""
permit2-signed-token-not-validated-as-pool-asset

Row-local manual repair. The generated matcher was broad and overclaimed from a
single regex surface. This replacement stays intentionally narrow and only
proves the owned fixture-smoke/source shape:

1. a public or external deposit/repay/mint-style function accepts a
   `PermitTransferFrom`-shaped parameter,
2. calls `permit2.permitTransferFrom(...)` with requestedAmount tied to the
   same `assets`/`amount` value later used for pool credit, and
3. never asserts `permit.permitted.token == asset()` or an equivalent expected
   pool-asset binding.

Submission posture: NOT_SUBMIT_READY. This detector is only fixture-smoke /
source-shape evidence until corpus-backed validation exists.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


_ENTRYPOINT_RE = re.compile(
    r"(?i)^(?:deposit|mint|repay|borrow|depositWithPermit|repayWithPermit|mintWithPermit)$"
)
_PERMIT_STRUCT_RE = re.compile(r"(?i)\bPermitTransferFrom\b")
_PERMIT_TRANSFER_CALL_RE = re.compile(r"(?i)\bpermit2\s*\.\s*permitTransferFrom\s*\(")
_REQUESTED_AMOUNT_RE = re.compile(
    r"(?is)\brequestedAmount\s*:\s*(?:assets|amount)\b|"
    r"\bSignatureTransferDetails\s*\([^)]*\b(?:assets|amount)\b[^)]*\)"
)
_CREDIT_RE = re.compile(
    r"(?is)\b(?:shares|balance|debt|credit|mintedShares)\b.*?(?:\+=|=)\s*(?:.*\bassets\b|\bamount\b)|"
    r"\b_mint\s*\([^;]*\b(?:assets|amount)\b[^;]*\)"
)
_TOKEN_CHECK_RE = re.compile(
    r"(?is)\bpermit\s*\.\s*permitted\s*\.\s*token\b\s*(?:==|!=)|"
    r"\brequire\s*\([^;{}]*\bpermit\s*\.\s*permitted\s*\.\s*token\b[^;{}]*\b(?:asset|underlying|poolAsset|expectedAsset)\b|"
    r"\bassertPermitToken(?:Matches|Is)?(?:Pool)?Asset\s*\("
)
_ASSET_CONTEXT_RE = re.compile(r"(?i)\b(?:asset\s*\(\s*\)|underlying|poolAsset|expectedAsset)\b")


def _source(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _has_unvalidated_pool_asset_permit_shape(function_src: str, contract_src: str) -> bool:
    if not _PERMIT_STRUCT_RE.search(function_src):
        return False
    if not _PERMIT_TRANSFER_CALL_RE.search(function_src):
        return False
    if not _REQUESTED_AMOUNT_RE.search(function_src):
        return False
    if not _CREDIT_RE.search(function_src):
        return False
    if not _ASSET_CONTEXT_RE.search(function_src) and not _ASSET_CONTEXT_RE.search(contract_src):
        return False
    if _TOKEN_CHECK_RE.search(function_src):
        return False
    return True


class Permit2SignedTokenNotValidatedAsPoolAsset(AbstractDetector):
    ARGUMENT = "permit2-signed-token-not-validated-as-pool-asset"
    HELP = (
        "Permit2 transfer path accepts a signed token choice from "
        "`PermitTransferFrom` but never binds `permit.permitted.token` to the "
        "vault's expected asset before crediting deposit/repay value."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "permit2-signed-token-not-validated-as-pool-asset.yaml"
    )
    WIKI_TITLE = "Permit2 transfer accepts arbitrary token as pool asset"
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. This row "
        "flags a deposit/repay-style entrypoint that consumes a user-supplied "
        "`PermitTransferFrom`, forwards it to `permit2.permitTransferFrom`, and "
        "credits pool value from the same requested amount without checking "
        "`permit.permitted.token` against the expected pool asset."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A vault accepts a Permit2 deposit for `assets=1_000_000` and pulls "
        "whatever token the signed permit names. Without an explicit token-equals-"
        "asset check, an attacker can sign for a worthless ERC20 yet receive "
        "credit as though the real pool asset was transferred."
    )
    WIKI_RECOMMENDATION = (
        "Require `permit.permitted.token == asset()` (or the exact expected pool "
        "asset variable) before calling `permit2.permitTransferFrom`. Keep this "
        "row NOT_SUBMIT_READY until broader live-source validation exists."
    )

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue

            contract_src = _source(contract)
            if "permitTransferFrom" not in contract_src:
                continue

            for function in contract.functions_and_modifiers_declared:
                if getattr(function, "visibility", "") not in {"public", "external"}:
                    continue
                if not _ENTRYPOINT_RE.search(function.name or ""):
                    continue

                function_src = _source(function)
                if not _has_unvalidated_pool_asset_permit_shape(function_src, contract_src):
                    continue

                info = [
                    function,
                    (
                        " accepts Permit2 transfer data and credits pool value "
                        "without binding `permit.permitted.token` to the expected "
                        "asset. NOT_SUBMIT_READY: fixture-smoke/source-shape proof only."
                    ),
                ]
                results.append(self.generate_result(info))
        return results
