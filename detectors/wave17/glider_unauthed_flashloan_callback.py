"""
glider-unauthed-flashloan-callback — generated from reference/patterns.dsl/glider-unauthed-flashloan-callback.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-unauthed-flashloan-callback.yaml
Source: hexens-glider/unauthenticated-flashloan-callbacks-allow-direct-invocation
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderUnauthedFlashloanCallback(AbstractDetector):
    ARGUMENT = "glider-unauthed-flashloan-callback"
    HELP = "Flashloan callback (`executeOperation`, `onFlashLoan`) performs sensitive work but does not validate `msg.sender` against a trusted flashloan provider. An attacker can invoke the callback directly with forged parameters to bypass the access-control assumptions of the surrounding state machine."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-unauthed-flashloan-callback.yaml"
    WIKI_TITLE = "Flashloan callback missing msg.sender check — forged-execution vector"
    WIKI_DESCRIPTION = "Aave's `executeOperation` and ERC-3156's `onFlashLoan` are invoked by the loan provider after the tokens have been credited. If the callback does not require `msg.sender == trustedProvider`, anyone can call it with any parameters. When the callback performs state writes / external calls / value transfers based on trust that it is running inside a genuine flashloan context, the attacker can exploit"
    WIKI_EXPLOIT_SCENARIO = "Contract `Strategy.executeOperation(assets, amounts, premiums, initiator, params)` decodes `params` into a swap instruction, trusting the caller to be Aave's `LendingPool`. The function performs the swap using `amounts[0]` which it assumes is already in its balance. Attacker calls `Strategy.executeOperation([USDC], [1e18], [0], attacker, swapParams)` directly — no tokens pulled in, no premium paid"
    WIKI_RECOMMENDATION = "Open the callback with `require(msg.sender == trustedProvider, \"not flashloan provider\")`. For multi-provider strategies, require `msg.sender` be among a whitelisted set. Additionally assert `initiator == address(this)` for Aave-style callbacks to ensure the loan was initiated from our own flashlo"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'executeOperation|onFlashLoan|executeFlashLoan|IFlashLoan'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(executeOperation|onFlashLoan|executeFlashLoan)$'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.body_contains_regex': '\\.call\\s*\\(|\\.transfer\\s*\\(|safeTransfer|safeApprove|_mint|_burn|\\w+\\s*=\\s*|delegatecall'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*msg\\.sender\\s*==\\s*(?:POOL|pool|provider|vault|AAVE|BALANCER|MORPHO|_pool|_provider|lendingPool|lender|flashLoanProvider)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-unauthed-flashloan-callback: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
