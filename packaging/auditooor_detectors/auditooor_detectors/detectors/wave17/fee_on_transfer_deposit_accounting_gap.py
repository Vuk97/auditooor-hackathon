"""
fee-on-transfer-deposit-accounting-gap — generated from reference/patterns.dsl/fee-on-transfer-deposit-accounting-gap.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fee-on-transfer-deposit-accounting-gap.yaml
Source: solodit/C0188
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FeeOnTransferDepositAccountingGap(AbstractDetector):
    ARGUMENT = "fee-on-transfer-deposit-accounting-gap"
    HELP = "deposit() calls safeTransferFrom(user, this, amount) and credits user.balance += amount without measuring received amount via balanceOf(address(this)) delta — fee-on-transfer tokens cause over-credit and reserve drain."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fee-on-transfer-deposit-accounting-gap.yaml"
    WIKI_TITLE = "Fee-on-transfer accounting gap on deposit path"
    WIKI_DESCRIPTION = "The deposit / supply entrypoint pulls tokens via safeTransferFrom and credits the caller's internal balance (or mints shares) using the passed `amount` rather than the measured delta between pre/post balanceOf(address(this)). Fee-on-transfer tokens (USDT fee mode, PAXG, deflationary) deliver strictly less than `amount`, so the internal accounting exceeds real holdings, and the gap is drained by la"
    WIKI_EXPLOIT_SCENARIO = "Pool supports a fee-on-transfer ERC20 (e.g. 2% transfer fee). Attacker calls deposit(1_000e18). Token delivers 980e18 to the pool; the code credits balances[msg.sender] += 1_000e18. Attacker repeats until booked balances exceed real holdings, then withdraws, draining the 20e18 gap per call from honest depositors."
    WIKI_RECOMMENDATION = "Snapshot balanceOf(address(this)) before safeTransferFrom, call it, then credit `balanceAfter - balanceBefore` (not the argument). Alternatively reject fee-on-transfer tokens at the registry level and assert the invariant on first deposit."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '(deposit|_deposit|supply)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(deposit|_deposit|supply|provide)'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.body_contains_regex': 'safeTransferFrom\\s*\\(|\\.transferFrom\\s*\\('}, {'function.writes_storage_matching': '(balance|balances|shares|deposited)'}, {'function.body_not_contains_regex': 'balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)|_received\\s*=\\s*balanceOf.*-|snapshotBalanceBefore|balanceAfter\\s*-\\s*balanceBefore'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fee-on-transfer-deposit-accounting-gap: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
