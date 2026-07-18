"""
gas-limited-loop-burns-input-before-full-payout — generated from reference/patterns.dsl/gas-limited-loop-burns-input-before-full-payout.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py gas-limited-loop-burns-input-before-full-payout.yaml
Source: auditooor-R75-nethermind-uspd-HIGH
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GasLimitedLoopBurnsInputBeforeFullPayout(AbstractDetector):
    ARGUMENT = "gas-limited-loop-burns-input-before-full-payout"
    HELP = "A redeem/burn function burns all of the user's shares up-front, then iterates positions to satisfy the burn. An intra-loop `if (gasleft() < MIN_GAS) break` early-exit means partial burns are possible — but because the full share amount is already burned, the unprocessed portion is not refunded, resu"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/gas-limited-loop-burns-input-before-full-payout.yaml"
    WIKI_TITLE = "Share redeem burns full amount before gas-limited payout loop — partial exit permanently loses shares"
    WIKI_DESCRIPTION = "To avoid DoS on positions with many allocations, withdrawal loops check `gasleft() < MIN_GAS` and break early if running out of gas. This is only correct when the state mutation is split: lock/escrow the shares first, then iterate, then re-credit whatever couldn't be processed. The anti-pattern is burning ALL shares upfront (`_burn(msg.sender, sharesAmount)`) and then relying on the full loop comp"
    WIKI_EXPLOIT_SCENARIO = "A liquidated position has 200 allocations (large). User Alice tries to burn 1000 cUSPD. burnShares() _burn's 1000 cUSPD from Alice up front, calls stabilizer.unallocateStabilizerFunds(1000). The while loop processes 150 allocations, hits MIN_GAS, breaks with remainingPoolShares=400. Alice receives ETH for only 600 shares but 1000 shares were burned — she permanently loses 400 cUSPD."
    WIKI_RECOMMENDATION = "Either (a) burn only the successfully-unallocated amount (move _burn after the loop and pass `poolSharesToUnallocate - remainingPoolShares`), or (b) re-credit the unprocessed shares back to the user at the end of the loop."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(gasleft|MIN_GAS|GAS_LIMIT|gasLimit).*(break|return)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(burn|redeem|unallocate|withdraw|claim)(Shares?|SharesFor|SharesOnBehalf|PoolShares?)$|^(shares?Burn|shares?Redeem|shares?Unallocate|shares?Withdraw)$'}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.body_contains_regex': '_burn\\s*\\(\\s*msg\\.sender'}, {'function.body_contains_regex': 'while\\s*\\([^)]+\\)\\s*\\{[^}]*gasleft\\(\\)\\s*<\\s*MIN_GAS[^}]*break'}, {'function.body_not_contains_regex': '_mint\\s*\\(\\s*msg\\.sender\\s*,\\s*(remaining|unprocessed|leftover)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — gas-limited-loop-burns-input-before-full-payout: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
