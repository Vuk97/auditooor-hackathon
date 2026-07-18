"""
hyperevm-usdc-evm-l1-decimals-conversion-missing — generated from reference/patterns.dsl/hyperevm-usdc-evm-l1-decimals-conversion-missing.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py hyperevm-usdc-evm-l1-decimals-conversion-missing.yaml
Source: monetrix-c4-2026-04-tokenmath
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class HyperevmUsdcEvmL1DecimalsConversionMissing(AbstractDetector):
    ARGUMENT = "hyperevm-usdc-evm-l1-decimals-conversion-missing"
    HELP = "EVM USDC is 6-dp; L1 spot USDC is 8-dp (`evmExtraWeiDecimals = -2`). Combining `usdc.balanceOf(...)` and `spotBalance(...).total` (or any precompile uint64 USDC value) without an explicit `usdcEvmToL1Wei` / `usdcL1WeiToEvm` conversion silently mis-prices the L1 portion by 100×."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/hyperevm-usdc-evm-l1-decimals-conversion-missing.yaml"
    WIKI_TITLE = "HyperEVM USDC arithmetic combines EVM 6-dp and L1 8-dp without conversion"
    WIKI_DESCRIPTION = "On Hyperliquid's HyperEVM, USDC is 6-decimal on the EVM side (standard ERC-20) and 8-decimal on the L1 side. The HIP-1 token registry encodes this with `evmExtraWeiDecimals = -2`, meaning EVM→L1 converts via `× 10^(−evmExtraWeiDecimals) = × 100` and L1→EVM via `÷ 100`. Any function that reads both an EVM-side balance (`IERC20.balanceOf(...)`) and an L1-side balance (`spotBalance(...).total`, `supp"
    WIKI_EXPLOIT_SCENARIO = "Lending pool reads `availableUsdc` as `usdc.balanceOf(address(this)) + spotBalance(address(this), USDC_TOKEN).total` to gate a withdrawal cap. Vault holds 1,000,000 USDC EVM-side (= 1e12 raw 6-dp) and 0 USDC L1-side. Function returns 1e12 + 0 = 1e12 — correct. Now an attacker crafts a state where 1 USDC sits L1-side: spotBalance.total = 1e8 (8-dp). Function returns 1e12 + 1e8 = 1.0001e12 raw — the"
    WIKI_RECOMMENDATION = "Centralize all EVM↔L1 USDC conversions in a `TokenMath` library and forbid raw arithmetic on values from different sides of the boundary. Specifically: (1) implement `usdcEvmToL1Wei(uint256 evm6dp) → uint64` (× 100, SafeCast) and `usdcL1WeiToEvm(uint64 l1_8dp) → uint256` (÷ 100, floor); (2) for prot"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'usdcEvmToL1Wei|usdcL1WeiToEvm|evmExtraWeiDecimals|EVM_TO_L1_PRECISION|spotBalance|HyperCoreConstants|hyperliquid|HyperEVM|hyperevm|TokenMath\\.evmToL1|TokenMath\\.l1WeiToEvm'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.body_contains_regex': '(?:usdc|USDC|asset|stable)\\.balanceOf\\s*\\(|IERC20\\s*\\([^)]*\\)\\.balanceOf|address\\(this\\)\\.balance\\b'}, {'function.body_contains_regex': 'spotBalance\\s*\\(|suppliedBalance\\s*\\(|spotUsdcEvm\\s*\\(|suppliedUsdcEvm\\s*\\(|\\.total\\b|abi\\.decode\\s*\\([^,]+,\\s*\\(\\s*uint64'}, {'function.body_contains_regex': '\\+\\s*[a-zA-Z_]*[Bb]alance|\\+\\s*[a-zA-Z_]*[Tt]otal|\\+\\s*[a-zA-Z_]*[Ss]upplied|\\+\\s*uint256\\s*\\(|>=\\s*[a-zA-Z_]*[Bb]al|<=\\s*[a-zA-Z_]*[Bb]al|return\\s+[a-zA-Z_]+\\s*\\+'}, {'function.body_not_contains_regex': 'usdcEvmToL1Wei|usdcL1WeiToEvm|TokenMath\\.evmToL1Wei|TokenMath\\.l1WeiToEvm|EVM_TO_L1_PRECISION|\\*\\s*100\\b|/\\s*100\\b|usdcL1WeiTo|usdcEvmTo|evmExtraWeiDecimals|spotUsdcEvm|suppliedUsdcEvm|\\.total\\s*/\\s*100|\\.total\\s*\\*\\s*1'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = False
    _INVERSE_CEI = False

    def _detect(self):
        results = []
        for c in self.contracts:
            if is_vendored_or_test_contract(c):
                continue
            if not eval_preconditions(c, self._PRECONDITIONS):
                continue
            for f in c.functions_and_modifiers_declared:
                if not self._INCLUDE_LEAF_HELPERS and is_leaf_helper(f):
                    continue
                if not eval_function_match(f, self._MATCH):
                    continue
                info = [f, f" — hyperevm-usdc-evm-l1-decimals-conversion-missing: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
