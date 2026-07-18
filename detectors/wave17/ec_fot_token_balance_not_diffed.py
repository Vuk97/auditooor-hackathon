"""
ec-fot-token-balance-not-diffed — generated from reference/patterns.dsl/ec-fot-token-balance-not-diffed.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ec-fot-token-balance-not-diffed.yaml
Source: economic-mining-R61
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EcFotTokenBalanceNotDiffed(AbstractDetector):
    ARGUMENT = "ec-fot-token-balance-not-diffed"
    HELP = "Deposit credits `amount` parameter directly instead of computing balanceAfter - balanceBefore; fee-on-transfer tokens cause over-crediting."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ec-fot-token-balance-not-diffed.yaml"
    WIKI_TITLE = "Deposit credits transfer `amount` directly — fee-on-transfer tokens over-credited"
    WIKI_DESCRIPTION = "The deposit function calls transferFrom(user, this, amount) and then adds `amount` directly to the user's internal balance without computing the actual received tokens as (balanceAfter - balanceBefore). For fee-on-transfer tokens, the contract receives less than `amount`. The protocol records more credit than it holds — an immediately exploitable deficit."
    WIKI_EXPLOIT_SCENARIO = "FoT token charges 5% on transfer. User calls deposit(1000). transferFrom moves 950 tokens (50 fee). Protocol credits user with 1000 (parameter value). User immediately withdraws 1000. Protocol must transfer 1000 but only holds 950 — 50 tokens stolen from other depositors."
    WIKI_RECOMMENDATION = "Use the balance-diff pattern: `uint256 before = token.balanceOf(address(this)); token.safeTransferFrom(...); uint256 received = token.balanceOf(address(this)) - before;` and credit `received` to the user, not `amount`. Add a comment noting FoT compatibility."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'safeTransferFrom|transferFrom|deposit|_deposit'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(deposit|addLiquidity|stake|_deposit|supply)'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.body_contains_regex': 'transferFrom\\s*\\(|safeTransferFrom\\s*\\('}, {'function.body_contains_regex': 'balances\\[\\w+\\]\\s*\\+=\\s*amount|deposited\\[\\w+\\]\\s*\\+=\\s*amount|userBalance.*\\+=.*amount|totalDeposits\\s*\\+=\\s*amount'}, {'function.body_not_contains_regex': 'balanceBefore|balanceAfter|before\\s*=.*balanceOf|after\\s*=.*balanceOf|balanceOf.*before|balanceOf.*after'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — ec-fot-token-balance-not-diffed: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
