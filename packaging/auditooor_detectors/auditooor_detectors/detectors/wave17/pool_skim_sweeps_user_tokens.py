"""
pool-skim-sweeps-user-tokens — generated from reference/patterns.dsl/pool-skim-sweeps-user-tokens.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py pool-skim-sweeps-user-tokens.yaml
Source: auditooor-round-34
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PoolSkimSweepsUserTokens(AbstractDetector):
    ARGUMENT = "pool-skim-sweeps-user-tokens"
    HELP = "AMM pool's skim/sync/sweep transfers balance-minus-reserves to caller without excluding pending user deposits. Anyone can drain commit-reveal / deposit-queue / pending-swap funds held on top of reserves."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/pool-skim-sweeps-user-tokens.yaml"
    WIKI_TITLE = "Pool skim() drains pending user deposits sitting above reserves"
    WIKI_DESCRIPTION = "An AMM or AMM-style pool exposes a permissionless skim/sync/sweep/rebalance/claimSurplus entry point that sends `balanceOf(address(this)) - reserves` to an arbitrary recipient. The pool also holds user deposits that have not yet been folded into `reserves` — commit-reveal batches, pending swaps, async mint/redeem requests, or any escrow layered above the AMM core. Because the skim treats every bal"
    WIKI_EXPLOIT_SCENARIO = "A v2-fork pool adds a commit-reveal deposit queue: users call `deposit(amt)` which transfers tokens in and credits `pending[user] += amt`, with reserves updated only at `reveal()` time. The fork keeps Uniswap v2's `skim(to)` verbatim — it transfers `balanceOf(address(this)) - reserves` to `to`. An attacker observes a large pending deposit in the mempool, back-runs it with `skim(attacker)`, and wal"
    WIKI_RECOMMENDATION = "Track the outstanding pending/escrow/queued total as an explicit state variable (e.g. `totalPending`) updated on every deposit / commit / queue-up and on every reveal / cancel / flush. In the skim/sync/sweep path, subtract that total before computing the surplus: `uint256 surplus = balanceOf(address"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'reserves?|reserve0|reserve1|totalReserves'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(skim|sweep|sync|rebalance|claimSurplus)$'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': 'balanceOf\\s*\\(\\s*address\\s*\\(\\s*this|_reserveBalance|\\.balance\\s*-\\s*reserve|balanceOf\\s*-\\s*reserves?'}, {'function.body_not_contains_regex': 'pending|escrow|committed|queued|unclaimed|reservedFor'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — pool-skim-sweeps-user-tokens: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
