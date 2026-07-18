"""
flashloan-callback-missing-initiator-check — generated from reference/patterns.dsl/flashloan-callback-missing-initiator-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py flashloan-callback-missing-initiator-check.yaml
Source: solodit-novel/slice_aa-Aave-executeOperation
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FlashloanCallbackMissingInitiatorCheck(AbstractDetector):
    ARGUMENT = "flashloan-callback-missing-initiator-check"
    HELP = "Flashloan callback validates msg.sender==pool but never checks `initiator == address(this)`. Attacker initiates a flashloan from the same pool that routes repayment tokens through the victim callback, triggering victim's callback logic as if the victim itself asked for the loan."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/flashloan-callback-missing-initiator-check.yaml"
    WIKI_TITLE = "Flashloan callback missing initiator==this check (piggyback attack)"
    WIKI_DESCRIPTION = "Aave's executeOperation is invoked by the LendingPool after a flashloan is initiated. If the callback checks `msg.sender == pool` but never checks `initiator == address(this)`, any third party can call `pool.flashLoan(victim, ...)` which routes tokens to the victim and invokes victim's executeOperation. The callback executes its strategy (approvals, swaps, repay logic) under external control."
    WIKI_EXPLOIT_SCENARIO = "Attacker calls `LendingPool.flashLoan(victimStrategy, [USDC], [1e8], attackerParams)`. The pool sends USDC to victim then calls `victim.executeOperation(USDC,1e8,0,attacker,params)`. Victim's callback only checks msg.sender==pool, so it decodes attacker-supplied params and executes the encoded instruction (swap, approve, withdraw) on victim's balance. Combined with a repayment path the attacker ge"
    WIKI_RECOMMENDATION = "Add `require(initiator == address(this), \"unauthorized initiator\")` alongside the msg.sender check. Only flashloans your own contract initiated should reach the sensitive code path."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'executeOperation|onFlashLoan|executeFlashLoan'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(executeOperation|onFlashLoan|executeFlashLoan)$'}, {'function.has_param_name_matching': 'initiator'}, {'function.body_contains_regex': 'require\\s*\\(\\s*msg\\.sender\\s*=='}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*initiator\\s*==\\s*address\\s*\\(\\s*this\\s*\\)|require\\s*\\(\\s*initiator\\s*==\\s*_self|initiator\\s*!=\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\)\\s*revert'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — flashloan-callback-missing-initiator-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
