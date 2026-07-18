"""
c4-repay-missing-onbehalf-owner-check — generated from reference/patterns.dsl/c4-repay-missing-onbehalf-owner-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py c4-repay-missing-onbehalf-owner-check.yaml
Source: code4arena/slice_aa-benddao
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class C4RepayMissingOnbehalfOwnerCheck(AbstractDetector):
    ARGUMENT = "c4-repay-missing-onbehalf-owner-check"
    HELP = "Repay-on-behalf function accepts a borrower address but never verifies msg.sender is authorized (e.g. borrower or NFT owner). Griefer can repay with wrong params to disrupt liquidation or settle at stale state."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/c4-repay-missing-onbehalf-owner-check.yaml"
    WIKI_TITLE = "Repay-on-behalf missing borrower/owner authorization"
    WIKI_DESCRIPTION = "BendDAO and similar peer-to-peer lending pools expose `isolateRepay(borrower, ...)` to let third parties settle someone else's loan. If the function never checks `msg.sender == borrower || msg.sender == nft.ownerOf(loan.tokenId)`, an attacker can race-repay a loan with dust to halt a legitimate liquidation."
    WIKI_EXPLOIT_SCENARIO = "Keeper initiates liquidation when loan becomes unhealthy. Borrower's ally front-runs with `isolateRepay(borrower, 1 wei)`; state is touched (e.g., lastAction timestamp updated) in a way that resets liquidation grace period. Liquidation now fails the grace check."
    WIKI_RECOMMENDATION = "Require `msg.sender == borrower` OR whitelist approved repayers via `approvedRepayer[borrower][msg.sender]`."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'isolateRepay|repayOnBehalf|repay\\(.*onBehalf'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(isolateRepay|repayOnBehalf|repayFor|_repay)'}, {'function.has_param_name_matching': 'onBehalfOf|borrower|user|onBehalf'}, {'function.writes_storage_matching': '.*'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*\\w*ownerOf\\s*\\(\\s*\\w+\\s*\\)\\s*==|require\\s*\\(\\s*\\w+\\s*==\\s*\\w+\\.owner|require\\s*\\(\\s*msg\\.sender\\s*==\\s*loan\\.borrower'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — c4-repay-missing-onbehalf-owner-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
