"""
state-change-between-check-and-use - generated from reference/patterns.dsl/state-change-between-check-and-use.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py state-change-between-check-and-use.yaml
Source: capability-lift:P1-11:state-change-between-check-and-use
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class StateChangeBetweenCheckAndUse(AbstractDetector):
    ARGUMENT = "state-change-between-check-and-use"
    HELP = "A mutable state guard is checked, an intervening mutator or external call can change that state, and the function then transfers, credits, burns, mints, or finalizes value without refreshing the checked predicate."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/state-change-between-check-and-use.yaml"
    WIKI_TITLE = "State changes between check and use"
    WIKI_DESCRIPTION = "Check-then-use code is unsafe when the checked state can change before the later value-bearing action. A status, health, balance, remaining amount, nonce, or claim guard must either be checked after the state-changing step or refreshed immediately before the transfer, credit, mint, burn, or finalization that relies on it."
    WIKI_EXPLOIT_SCENARIO = "A claim path checks `!claimed[id]`, runs a sync step that may mark the claim as consumed, then credits rewards using the stale pre-sync result. An order path checks `order.open`, calls a settlement updater that closes or partially fills the order, then pays proceeds from the stale order fields. A lending path checks health before interest accrual, accrues debt, then withdraws collateral without a "
    WIKI_RECOMMENDATION = "Move the state-changing refresh, accrual, settlement, or checkpoint before the guard, then validate the fresh state immediately before the value-bearing use. If the sequence must include an external callback, add a shared reentrancy lock and revalidate the checked predicate after control returns."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(require\\s*\\(|if\\s*\\(|status|state|active|open|enabled|valid|allowed|approved|health|solvent|balance|collateral|debt|nonce|claim|claimed|filled|remaining|settled|finalized|locked|paused)'}, {'contract.source_matches_regex': '(?i)(sync|update|refresh|accrue|checkpoint|settle|fill|consume|mark|cancel|close|finalize|execute|apply|safeTransfer|transferFrom|transfer\\s*\\(|\\.call\\s*\\()'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': '(?i)^_?(claim|withdraw|redeem|borrow|repay|liquidate|settle|fill|match|execute|cancel|finalize|release|consume|use|mint|burn|transfer)[A-Za-z0-9_]*$'}, {'function.body_ordered_regex': {'first': '(?i)(require\\s*\\([^;]*(active|open|enabled|valid|allowed|approved|status|state|health|solvent|balance|collateral|debt|nonce|claim|claimed|filled|remaining|settled|finalized|locked|paused)[^;]*\\)|if\\s*\\([^)]*(active|open|enabled|valid|allowed|approved|status|state|health|solvent|balance|collateral|debt|nonce|claim|claimed|filled|remaining|settled|finalized|locked|paused)[^)]*\\)\\s*(?:\\{?\\s*)?(?:revert|return))', 'second': '(?i)((_?(sync|update|refresh|accrue|checkpoint|settle|fill|consume|mark|cancel|close|finalize|execute|apply)[A-Za-z0-9_]*|[A-Za-z0-9_]+\\.(sync|update|refresh|accrue|checkpoint|settle|fill|consume|mark|cancel|close|finalize|execute|apply)[A-Za-z0-9_]*|safeTransferFrom|transferFrom|safeTransfer|transfer|\\.call|\\.delegatecall)\\s*\\([\\s\\S]{0,1200}(safeTransfer|transferFrom|transfer\\s*\\(|_mint|_burn|mint\\s*\\(|burn\\s*\\(|balances?\\s*\\[|credits?\\s*\\[|proceeds\\s*\\[|rewards?\\s*\\[|orders?\\s*\\[|positions?\\s*\\[|collateral\\s*(?:\\[|-=|\\+=|=)|debt\\s*(?:\\[|-=|\\+=|=)|finalized\\s*\\[|settled\\s*\\[|claimed\\s*\\[))', 'ignore_comments_and_strings': True}}, {'function.body_not_contains_regex': '(?i)\\b(fresh(State|Status|Balance|Health|Order|Position)?|statusAfter|stateAfter|balanceAfter|healthAfter|remainingAfter|collateralAfter|debtAfter|recheck|rechecked|revalidated|validateAfter|assertFresh)\\b\\s*=|\\brequire\\s*\\([^;]*(fresh|After|recheck|revalidated|validateAfter|assertFresh)'}, {'function.body_not_contains_regex': '(?i)\\b(nonReentrant|ReentrancyGuard|_reentrancyGuardEntered|locked\\s*=\\s*true|reentrancyLock)\\b'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" - state-change-between-check-and-use: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
