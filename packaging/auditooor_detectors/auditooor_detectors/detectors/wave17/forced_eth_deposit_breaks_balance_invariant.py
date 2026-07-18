"""
forced-eth-deposit-breaks-balance-invariant — generated from reference/patterns.dsl/forced-eth-deposit-breaks-balance-invariant.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py forced-eth-deposit-breaks-balance-invariant.yaml
Source: solodit-cluster/R34
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ForcedEthDepositBreaksBalanceInvariant(AbstractDetector):
    ARGUMENT = "forced-eth-deposit-breaks-balance-invariant"
    HELP = "Contract enforces `address(this).balance == trackedEth` as an invariant; attacker force-sends ETH (e.g., `selfdestruct(contract)`, coinbase reward, pre-deployed funding) which does NOT trigger receive()/fallback. The tracked value stays stale, the invariant breaks, and every guarded function reverts"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/forced-eth-deposit-breaks-balance-invariant.yaml"
    WIKI_TITLE = "Forced ETH deposit via selfdestruct breaks `balance == tracked` invariant (DoS)"
    WIKI_DESCRIPTION = "A contract maintains an internal ETH accounting variable (e.g., `trackedEth`, `totalDeposits`, `reserveETH`) and guards critical functions with `require(address(this).balance == trackedEth)` or `assert(address(this).balance == trackedEth)`. Solidity treats `selfdestruct(target)`, pre-deployment address-funding, and block.coinbase rewards as ETH arrivals that bypass receive()/fallback. The attacker"
    WIKI_EXPLOIT_SCENARIO = "A DEX pool enforces `require(address(this).balance == reserveETH)` at the top of swap(), addLiquidity(), and removeLiquidity(). Attacker deploys a throwaway contract funded with 1 wei, calls `selfdestruct(pool)`. The pool's balance ticks up by 1 wei with no receive() call, reserveETH stays unchanged, the equality invariant fails, and the entire pool is permanently frozen — liquidity providers cann"
    WIKI_RECOMMENDATION = "Never use `==` on `address(this).balance`. Use `>=` (the contract may hold forced donations) and treat any surplus as sweepable/dust rather than corruption. If strict accounting is needed, compute invariant-relevant balance from accounting state alone, never from `address(this).balance`. For protoco"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': 'address\\s*\\(\\s*this\\s*\\)\\.balance\\s*==\\s*\\w+|require\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\.balance\\s*==|assert\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\.balance\\s*=='}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — forced-eth-deposit-breaks-balance-invariant: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
