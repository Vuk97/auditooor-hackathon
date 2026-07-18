"""
dh-pool-burn-callback-reenters-burn — generated from reference/patterns.dsl/dh-pool-burn-callback-reenters-burn.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py dh-pool-burn-callback-reenters-burn.yaml
Source: defihacklabs-2024-12/CloberDEX
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DhPoolBurnCallbackReentersBurn(AbstractDetector):
    ARGUMENT = "dh-pool-burn-callback-reenters-burn"
    HELP = "Pool `burn` (LP redemption) routes through an external strategy/hook callback without a reentrancy guard. The attacker's strategy can re-enter burn() mid-callback and drain the pool twice."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/dh-pool-burn-callback-reenters-burn.yaml"
    WIKI_TITLE = "Pool burn callback to strategy hook is reentrant"
    WIKI_DESCRIPTION = "A constant-product / order-book AMM exposes a `burn` redemption path that invokes an external `burnHook(...)` (or `onBurn`, `afterBurn`) callback on a caller-nominated strategy contract. The hook is intended for rebalancing logic, but the burn function holds no reentrancy guard and the strategy is attacker-chosen at pool creation. The attacker's contract re-enters `burn()` inside the callback, dou"
    WIKI_EXPLOIT_SCENARIO = "Clober DEX Rebalancer (Dec 2024, $501K on Base): attacker (1) flash-loans WETH, (2) opens a rebalancer pool with `strategy = address(attacker)` against a fake ERC20, (3) mints LP, (4) burns LP. Inside `burnHook(...)` the attacker re-calls `burn` on the same pool — totalSupply reads the pre-burn value both times, so both burns pay out the full share of WETH. Net: attacker walks off with the pool's "
    WIKI_RECOMMENDATION = "Add `nonReentrant` to every mutative pool entrypoint (burn / mint / swap) that calls out to a strategy hook. Alternatively, compute and snapshot all payouts BEFORE invoking the external hook, and ensure totalSupply / reserves are decremented atomically. Consider making the hook a pre-registered allo"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'burn\\s*\\(|mint\\s*\\(|onBurn|burnHook|beforeBurn|afterBurn'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(burn|redeem|removeLiquidity|withdrawLiquidity)$'}, {'function.body_contains_regex': '\\.burnHook\\s*\\(|\\.onBurn\\s*\\(|\\.afterBurn\\s*\\(|\\.beforeBurn\\s*\\(|IHook\\w*\\s*\\(\\s*strategy\\s*\\)|IStrategy\\w*\\s*\\(\\s*\\w+\\s*\\)\\.'}, {'function.body_not_contains_regex': 'nonReentrant|_NOT_ENTERED|ReentrancyGuard|_locked\\s*=\\s*true'}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — dh-pool-burn-callback-reenters-burn: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
