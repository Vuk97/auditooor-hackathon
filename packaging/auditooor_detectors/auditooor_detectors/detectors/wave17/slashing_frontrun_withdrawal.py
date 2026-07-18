"""
slashing-frontrun-withdrawal — generated from reference/patterns.dsl/slashing-frontrun-withdrawal.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py slashing-frontrun-withdrawal.yaml
Source: solodit-cluster-C0287
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SlashingFrontrunWithdrawal(AbstractDetector):
    ARGUMENT = "slashing-frontrun-withdrawal"
    HELP = "Admin-gated slash() operates only on the current on-vault balance and never touches pendingWithdrawals — a staker who observes the slash tx in the mempool can frontrun it with their own withdraw() and escape the penalty entirely."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/slashing-frontrun-withdrawal.yaml"
    WIKI_TITLE = "Slashing bypassable via withdrawal frontrun"
    WIKI_DESCRIPTION = "Restaking and staking-vault designs split balance into `active` and `pendingWithdrawal` buckets with a delay. A slasher that reduces only the active bucket (or the last-known pre-withdrawal balance) lets a misbehaving operator observe the slash tx in the mempool, call `withdraw()` first to shift funds into the pending bucket, and receive them intact after the delay — the slash either reverts with "
    WIKI_EXPLOIT_SCENARIO = "An oracle node commits fraud. The governance DSS submits `slash(operator, 1000e18)`. Operator's MEV bot sees the pending tx, frontruns with `withdraw(1000e18)` which moves the 1000 tokens into `pendingWithdrawals[operator]` and zeros `balances[operator]`. The slash tx runs next: it reads `balances[operator] == 0` and either reverts or applies zero penalty. After the 7-day withdrawal window the ope"
    WIKI_RECOMMENDATION = "Slashing must (1) include pendingWithdrawals in the penalizable set — iterate the queue and reduce each pending claim pro-rata, (2) block or mark pending withdrawals during an open slashing window so no withdrawal can settle while a slash is accruing, and (3) enforce a slash-grace period longer than"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'pendingWithdrawals|withdrawRequests|slashing|slashQueue|slashWindow'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'slash|_slash|slashOperator|applySlash|processSlashing'}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyAdmin', 'onlyRoles', 'onlyDSS', 'onlySlasher'], 'negate': False}}, {'function.body_not_contains_regex': 'pendingWithdrawals|slashPending|include.*withdrawal|slashOnWithdraw'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — slashing-frontrun-withdrawal: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
