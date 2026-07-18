"""
aave-v3-flashloan-callback-executeoperation-lacks-sender-validation - generated from reference/patterns.dsl/aave-v3-flashloan-callback-executeoperation-lacks-sender-validation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py aave-v3-flashloan-callback-executeoperation-lacks-sender-validation.yaml
Source: hexens-glider/aave-v3-flashloan-callback-execute-operation-lacks
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AaveV3FlashloanCallbackExecuteoperationLacksSenderValidation(AbstractDetector):
    ARGUMENT = "aave-v3-flashloan-callback-executeoperation-lacks-sender-validation"
    HELP = "Aave V3 flashloan receiver `executeOperation` performs callback logic without validating `msg.sender` as the trusted pool."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/aave-v3-flashloan-callback-executeoperation-lacks-sender-validation.yaml"
    WIKI_TITLE = "Aave V3 flashloan executeOperation missing sender validation"
    WIKI_DESCRIPTION = "Aave V3 flashloan receivers expose `executeOperation(...)` as the callback entrypoint invoked by the pool after funds are issued. If the receiver performs approvals, transfers, swaps, or other sensitive work before verifying `msg.sender` is the canonical Aave pool, any external caller can forge the callback and trigger the post-loan logic out of context."
    WIKI_EXPLOIT_SCENARIO = "A strategy contract expects `executeOperation` to run only after the pool sent tokens. The callback immediately approves or transfers assets using the supplied arrays. Because it never checks `msg.sender == POOL`, an attacker calls `executeOperation` directly and executes the trusted callback path on the contract's existing balances."
    WIKI_RECOMMENDATION = "Require `msg.sender == address(POOL)` at the top of `executeOperation` before any asset movement or other privileged callback logic."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'executeOperation\\s*\\('}]
    _MATCH = [{'function.name_matches': '^executeOperation$'}, {'function.kind': 'external_or_public'}, {'function.body_contains_regex': 'transfer|approve|call|delegatecall|swap'}, {'function.body_not_contains_regex': 'msg\\.sender\\s*(==|!=)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" - aave-v3-flashloan-callback-executeoperation-lacks-sender-validation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
