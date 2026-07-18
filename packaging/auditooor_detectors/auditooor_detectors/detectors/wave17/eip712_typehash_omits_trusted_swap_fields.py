"""
eip712-typehash-omits-trusted-swap-fields — generated from reference/patterns.dsl/eip712-typehash-omits-trusted-swap-fields.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py eip712-typehash-omits-trusted-swap-fields.yaml
Source: defimon-2026-04-23-giddy-1.3M
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Eip712TypehashOmitsTrustedSwapFields(AbstractDetector):
    ARGUMENT = "eip712-typehash-omits-trusted-swap-fields"
    HELP = "EIP-712 _validateAuthorization helper hashes only the opaque `data` field of a SwapInfo struct, leaving aggregator/fromToken/toToken/fromAmount/minToAmount unsigned. Anyone with a leaked legitimate signature replays the same sig with mutated trusted fields — the on-chain code routes the swap as the "
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/eip712-typehash-omits-trusted-swap-fields.yaml"
    WIKI_TITLE = "EIP-712 typehash covers only `data` field of swap struct, leaving aggregator/token/amount unsigned"
    WIKI_DESCRIPTION = "Aggregator-routing contracts that authorize off-chain quotes via EIP-712 build the digest as `keccak256(abi.encode(TYPEHASH, keccak256(swapInfo.data)))` — covering only the opaque `data` bytes that the aggregator-specific call payload travels in. The runtime SwapInfo struct also carries `aggregator`, `fromToken`, `toToken`, `fromAmount`, `minToAmount` — all of which the contract dereferences AFTER"
    WIKI_EXPLOIT_SCENARIO = "Giddy.co (Apr 23 2026, ~$1.3M USDC drained, tx 0x5edb66a4c2ea55bba95d36d27713e3bb1c67c3c4199a8a1759e754c6f25482e5): the SwapInfo signing helper computed `digest = _hashTypedDataV4(keccak256(abi.encode(SWAPINFO_TYPEHASH, keccak256(swapInfo.data))))`. Attacker scraped the mempool for any prior valid (sig, swapInfo) blob. They then submitted swap() with the same sig but mutated swapInfo.fromToken=USD"
    WIKI_RECOMMENDATION = "The signed typehash MUST list every field the contract subsequently trusts. Define `bytes32 constant SWAPINFO_TYPEHASH = keccak256('SwapInfo(address aggregator,address fromToken,address toToken,uint256 fromAmount,uint256 minToAmount,address receiver,bytes data)')`, and pass each field to abi.encode "

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(SwapInfo|SwapDescription|SwapParams|swapAuth|aggregator|router)'}, {'contract.source_matches_regex': '(?i)(EIP712|_TYPEHASH|hashTypedData|_hashTypedDataV4|DOMAIN_SEPARATOR)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '(?i)(validateAuthorization|verifySwap|verifyAuth|_verify|_validate|hashSwap|_hashSwapInfo|_hashSwapDescription|recoverSwapSigner|verifyQuote|hashSwapStruct)'}, {'function.has_param_struct_named': 'Swap'}, {'function.body_contains_regex': '(?i)(_TYPEHASH|hashTypedDataV4|_hashTypedData\\s*\\()'}, {'function.body_contains_regex': '(?i)abi\\.encode\\s*\\(\\s*\\w*_?TYPEHASH\\s*,\\s*[^)]*\\bkeccak256\\s*\\(\\s*\\w+\\.data\\s*\\)'}, {'function.body_not_contains_regex': '(?i)abi\\.encode\\s*\\([^)]*\\b(aggregator|fromToken|toToken|fromAmount|minToAmount|toAmount|amountIn|amountOut|slippage|receiver|to)\\b'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" — eip712-typehash-omits-trusted-swap-fields: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
