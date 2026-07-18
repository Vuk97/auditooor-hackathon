"""
stable-v4-fee-sentinel-domain-mismatch

Hand-written cross-contract detector seed for Uniswap v4 hooks that store a
PoolKey fee value and later reuse the same value as protocol arithmetic fee
percentage. The dangerous shape is accepting the v4 dynamic-fee sentinel into
PoolKey.fee without excluding it from hook fee math.
"""

from __future__ import annotations

import re

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


_POOLKEY_FEE_RE = re.compile(
    r"PoolKey\s+memory\s+\w+\s*=\s*PoolKey\s*\([^;]*"
    r"fee\s*:\s*(?:SafeCast\.)?toUint24\s*\([^)]*(?:lpFee|feePercentage)",
    re.IGNORECASE | re.DOTALL,
)
_FEE_ARITH_RE = re.compile(
    r"(?:mulDiv\s*\([^;]*(?:lpFeePercentage|_lpFeePercentage)[^;]*FEE_PRECISION|"
    r"(?:lpFeePercentage|_lpFeePercentage)\s*[,*/][^;]*FEE_PRECISION)",
    re.IGNORECASE | re.DOTALL,
)
_SENTINEL_GUARD_RE = re.compile(
    r"(DYNAMIC_FEE_FLAG|MAX_LP_FEE|isDynamicFee|"
    r"(?:lpFeePercentage|_lpFeePercentage)\s*(?:<=|<)\s*(?:MAX_|LPFeeLibrary\.MAX|1_000_000|1000000))",
    re.IGNORECASE,
)


class StableV4FeeSentinelDomainMismatch(AbstractDetector):
    ARGUMENT = "stable-v4-fee-sentinel-domain-mismatch"
    HELP = (
        "Uniswap v4 PoolKey fee accepts a hook fee value that is later used as "
        "percentage arithmetic without excluding dynamic-fee sentinels."
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/stable-v4-fee-sentinel-domain-mismatch.yaml"
    WIKI_TITLE = "Uniswap v4 fee sentinel reused as StableSwap arithmetic fee"
    WIKI_DESCRIPTION = (
        "Uniswap v4 reserves sentinel fee encodings such as the dynamic-fee flag "
        "for PoolKey semantics. Hook implementations that store the same value "
        "as an LP fee percentage must reject those sentinels before fee math."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A factory deploys a hook with LPFeeLibrary.DYNAMIC_FEE_FLAG. PoolKey "
        "initialization accepts it as dynamic-fee configuration, but hook fee "
        "calculation treats the sentinel as an oversized percentage and normal "
        "swaps revert or charge impossible fees."
    )
    WIKI_RECOMMENDATION = (
        "Reject dynamic-fee sentinel values and require the fee to be within the "
        "same maximum domain used by arithmetic fee calculation before building "
        "PoolKey or storing the value."
    )

    def _all_contract_source(self) -> str:
        parts: list[str] = []
        for contract in self.contracts:
            try:
                parts.append(contract.source_mapping.content or "")
            except Exception:
                continue
        return "\n".join(parts)

    def _detect(self):
        results = []
        all_source = self._all_contract_source()
        if not _FEE_ARITH_RE.search(all_source):
            return results

        for contract in self.contracts:
            for function in contract.functions_and_modifiers_declared:
                if str(getattr(function, "name", "")).startswith("slither"):
                    continue
                try:
                    body = function.source_mapping.content or ""
                except Exception:
                    body = ""
                if not _POOLKEY_FEE_RE.search(body):
                    continue
                if _SENTINEL_GUARD_RE.search(body):
                    continue
                info = [
                    function,
                    " accepts a PoolKey fee value that is also used as LP fee arithmetic without a sentinel/domain guard",
                ]
                results.append(self.generate_result(info))
        return results
