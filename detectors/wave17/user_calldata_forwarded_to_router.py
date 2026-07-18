"""
user-calldata-forwarded-to-router — generated from reference/patterns.dsl/user-calldata-forwarded-to-router.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py user-calldata-forwarded-to-router.yaml
Source: DeFiHackLabs: TokenHolder/BorrowerOperationsV6 (2025-10, 20 WBNB) + SizeCredit LeverageUp (2025-08, $19.7K) — user-supplied bytes forwarded as calldata to a DEX router / whitelisted executor, enabling arbitrary selector like transferFrom(victim, attacker, amount)
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UserCalldataForwardedToRouter(AbstractDetector):
    ARGUMENT = "user-calldata-forwarded-to-router"
    HELP = "Function forwards a user-supplied bytes payload to a whitelisted integration (DEX router, margin executor) without restricting the selector or target. The integration already holds token allowances, so an attacker crafts calldata like transferFrom(victim, attacker, amount)."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/user-calldata-forwarded-to-router.yaml"
    WIKI_TITLE = "User-supplied calldata forwarded to trusted router with allowances"
    WIKI_DESCRIPTION = "The contract accepts a bytes argument (sellingCode / callData / swapData / payload) and forwards it via a low-level call into a downstream integration — a DEX aggregator, 1inch router, margin manager, or whitelisted executor. Because users have pre-approved the integration for arbitrary tokens, the payload can encode `transferFrom(anyUser, attacker, allowance)` and the integration, trusting its ca"
    WIKI_EXPLOIT_SCENARIO = "TokenHolder BorrowerOperationsV6 (2025-10, 20 WBNB). The sell() function took (uint256 loadId, bytes sellingCode, address tokenHolder, address inchRouter, address integratorFeeAddress, address whitelistedDex) and forwarded sellingCode via low-level call to inchRouter. Attacker supplied sellingCode = abi.encodeWithSignature('privilegedLoan(address,uint256)', WBNB, 20 ether) and a same-contract `pri"
    WIKI_RECOMMENDATION = "Never forward raw user bytes to a contract that holds user allowances. Either (a) whitelist permitted selectors by parsing `bytes4 sel = bytes4(data[0:4]); require(allowedSelector[sel])`, (b) constrain the target to a list of known-safe handlers, or (c) decode the payload into a typed struct and re-"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(router|aggregator|executor|dex|LeverageUp|BorrowerOperations|margin|integrator)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_param_of_type': 'bytes'}, {'function.has_param_name_matching': 'sellingCode|callData|swapData|executeParams|payload|data|calls|multicallData|execData'}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.body_contains_regex': '\\.call\\s*\\(|\\.delegatecall\\s*\\(|\\.functionCall\\s*\\(|execute\\s*\\(.*\\bdata\\b|\\.swap\\s*\\('}, {'function.body_not_contains_regex': 'bytes4\\s*\\(\\s*(sellingCode|callData|data|payload)|allowedSelector|selectorAllowed|whitelistedSelector|_allowedTargets\\[|allowedTarget\\['}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — user-calldata-forwarded-to-router: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
