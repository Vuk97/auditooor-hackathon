"""
r94-loop-erc20-approve-nonzero-to-nonzero-race-condition — generated from reference/patterns.dsl/r94-loop-erc20-approve-nonzero-to-nonzero-race-condition.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-erc20-approve-nonzero-to-nonzero-race-condition.yaml
Source: solodit-28942-trailofbits-maple-labs
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopErc20ApproveNonzeroToNonzeroRaceCondition(AbstractDetector):
    ARGUMENT = "r94-loop-erc20-approve-nonzero-to-nonzero-race-condition"
    HELP = "r94-loop-erc20-approve-nonzero-to-nonzero-race-condition"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-erc20-approve-nonzero-to-nonzero-race-condition.yaml"
    WIKI_TITLE = "r94-loop-erc20-approve-nonzero-to-nonzero-race-condition"
    WIKI_DESCRIPTION = "r94-loop-erc20-approve-nonzero-to-nonzero-race-condition"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-erc20-approve-nonzero-to-nonzero-race-condition"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(ERC20|Token|Approve|Allowance)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(^approve$|^_approve$|approveErc20|approveToken|setAllowance)'}, {'function.source_matches_regex': '(allowances\\s*\\[\\s*\\w+\\s*\\]\\s*\\[\\s*\\w+\\s*\\]\\s*=\\s*\\w*(value|amount)|allowance\\s*\\[\\s*\\w+\\s*\\]\\s*\\[\\s*\\w+\\s*\\]\\s*=\\s*\\w*(value|amount)|_allowances\\s*\\[\\s*\\w+\\s*\\]\\s*\\[\\s*\\w+\\s*\\]\\s*=\\s*\\w*(value|amount))'}, {'function.not_source_matches_regex': '(require\\s*\\(\\s*\\w*(amount|value)\\s*==\\s*0\\s*\\|\\|\\s*\\w*allowance\\s*\\[|require\\s*\\(\\s*allowances\\s*\\[[\\s\\S]{0,80}?\\]\\s*==\\s*0|currentAllowance\\s*==\\s*0|increaseAllowance\\s*\\(|decreaseAllowance\\s*\\(|approveFromZero|forceApprove)'}]

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
                info = [f, f" — r94-loop-erc20-approve-nonzero-to-nonzero-race-condition: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
