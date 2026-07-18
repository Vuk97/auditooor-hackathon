"""
read-only-reentrancy-view — generated from reference/patterns.dsl/read-only-reentrancy-view.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py read-only-reentrancy-view.yaml
Source: solodit-cluster/C0117-partial+balancer-readonly
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ReadOnlyReentrancyView(AbstractDetector):
    ARGUMENT = "read-only-reentrancy-view"
    HELP = "Public/external view returns a value derived from live accounting state (balance/reserve/totalSupply/sharePrice) without a nonReentrant(View) guard; an external integrator that queries this view during a callback receives a stale answer and can be economically exploited."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/read-only-reentrancy-view.yaml"
    WIKI_TITLE = "Read-only reentrancy: unguarded view reads mid-mutation accounting"
    WIKI_DESCRIPTION = "A view (or public getter) on a contract that also exposes a callback surface (ERC20/721/1155 receiver, flash-loan callback) returns a value computed from live balance/reserve/supply/sharePrice state without a read-side reentrancy guard. When the host contract performs an external call into a user-controlled callee mid-mutation, any sibling contract that quotes this view during the callback observe"
    WIKI_EXPLOIT_SCENARIO = "The pool exposes `getSharePrice()` computed from `totalAssets / totalSupply`. The pool also integrates a flash-loan / ERC777 transfer path that briefly decrements `totalAssets` before the settling mint. A lending protocol trusts `getSharePrice()` as an oracle. Attacker triggers the flash-loan callback, re-enters the lender (not the pool) inside that callback, and the lender reads a deflated `getSh"
    WIKI_RECOMMENDATION = "Apply a read-side reentrancy guard to every externally observable view that depends on live accounting state (OpenZeppelin has no built-in; use Balancer's `ensureNotInVaultContext` pattern or Curve's `nonreentrant('lock')` applied to the view). Alternatively, derive the quoted value from a TWAP / ch"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_body_matching': 'onERC(20|721|1155)|IERC(20|721|1155)|IFlashLoan|receiveFlashLoan|executeOperation'}, {'contract.has_state_var_matching': '(balance|reserve|totalSupply|totalAssets|sharePrice|pricePerShare|virtualPrice|getRate)'}, {'contract.has_external_call_to': '(?i)receiveFlashLoan|executeOperation|onFlashLoan|onERC(20|721|1155)Received|tokensReceived'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': {'regex': '\\bview\\b|\\bpure\\b', 'negate': False}}, {'function.reads_storage_matching': '(balance|reserve|totalSupply|totalAssets|sharePrice|pricePerShare|virtualPrice|getRate)'}, {'function.has_modifier': {'includes': ['nonReentrant', 'nonreentrant', 'nonReentrantView', 'whenNotInVaultContext', 'ensureNotInVaultContext', 'noReentrancy', 'lock'], 'negate': True}}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — read-only-reentrancy-view: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
