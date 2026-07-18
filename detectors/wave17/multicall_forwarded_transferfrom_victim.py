"""
multicall-forwarded-transferfrom-victim — generated from reference/patterns.dsl/multicall-forwarded-transferfrom-victim.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py multicall-forwarded-transferfrom-victim.yaml
Source: defihacklabs/2025-07-MulticallWithETH,2025-08-MulticallWithXera
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MulticallForwardedTransferfromVictim(AbstractDetector):
    ARGUMENT = "multicall-forwarded-transferfrom-victim"
    HELP = "multicall/aggregate function forwards `target.call(callData)` to user-supplied targets with user-supplied calldata. Because the contract holds ERC20 allowances granted for normal ops, any approval becomes drainable by anyone crafting a transferFrom call through the multicall."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/multicall-forwarded-transferfrom-victim.yaml"
    WIKI_TITLE = "multicall with arbitrary target drains approved ERC20 from victims"
    WIKI_DESCRIPTION = "Multicall utilities that do not restrict the `target` of each subcall allow an attacker to synthesize arbitrary external calls from the contract's context. When the contract itself holds ERC20 allowances from real users (e.g. MEV routers, aggregators that pre-approve tokens for efficiency), the attacker encodes `transferFrom(victim, attacker, X)` as one of the multicall calls. Because msg.sender o"
    WIKI_EXPLOIT_SCENARIO = "MulticallWithETH (Jul 2025, ~10k USDT): victim pre-approved USDC to the multicall contract. Attacker calls `multicall([Call{target: USDC, data: transferFrom(victim, attacker, victim.balance)}])`. Inside the multicall, USDC.transferFrom checks allowance[victim][multicall], finds the approval, and moves the tokens."
    WIKI_RECOMMENDATION = "Restrict multicall targets to `address(this)` (OpenZeppelin Multicall) so the aggregator only calls itself. If cross-target is intentional, maintain a target allowlist. Never hold ERC20 allowances on a contract with arbitrary-call multicall."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'multicall|aggregate|batch'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(multicall|aggregate|aggregate3|batch|execute)'}, {'function.body_contains_regex': 'for\\s*\\([^)]*\\)\\s*\\{[^}]*\\.call\\s*\\(|calls\\s*\\[\\s*\\w+\\s*\\]\\.target\\.call'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*\\w*target\\w*\\s*==\\s*address\\s*\\(\\s*this\\s*\\)|target\\s*!=\\s*address\\s*\\(\\s*0\\s*\\).*require.*allowlisted|isAllowedTarget\\s*\\[\\s*\\w*target'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — multicall-forwarded-transferfrom-victim: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
