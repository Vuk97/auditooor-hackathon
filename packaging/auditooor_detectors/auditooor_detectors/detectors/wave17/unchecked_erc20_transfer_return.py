"""
unchecked-erc20-transfer-return — generated from reference/patterns.dsl/unchecked-erc20-transfer-return.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py unchecked-erc20-transfer-return.yaml
Source: solodit-cluster-C0154
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UncheckedErc20TransferReturn(AbstractDetector):
    ARGUMENT = "unchecked-erc20-transfer-return"
    HELP = "Raw ERC20 .transfer()/.transferFrom() without checking the bool return — USDT-style tokens silently fail."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/unchecked-erc20-transfer-return.yaml"
    WIKI_TITLE = "Unchecked ERC20 transfer/transferFrom return value"
    WIKI_DESCRIPTION = "ERC20 tokens are permitted to return false on failure rather than revert. USDT and a handful of other widely-used tokens return no bool at all. Code that calls .transfer/.transferFrom and ignores the return can mis-credit users, under-collect fees, or corrupt accounting when the underlying transfer silently fails."
    WIKI_EXPLOIT_SCENARIO = "Protocol assumes `token.transfer(recipient, amount)` succeeded because the EVM call did not revert. The token actually returned false (or nothing, coerced as zero) and no tokens moved. Protocol state is updated as if the recipient received tokens — permanent inventory divergence, and for deposit flows, free balance credits."
    WIKI_RECOMMENDATION = "Wrap all ERC20 transfers in OpenZeppelin's SafeERC20 (safeTransfer/safeTransferFrom), or at minimum `require(token.transfer(...), \"transfer failed\")`. Treat missing-return tokens explicitly."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.body_contains_regex': '\\.transfer\\s*\\(|\\.transferFrom\\s*\\('}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — unchecked-erc20-transfer-return: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
