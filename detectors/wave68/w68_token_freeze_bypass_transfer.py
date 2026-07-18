"""
w68-token-freeze-bypass-transfer - generated from reference/patterns.dsl/w68-token-freeze-bypass-transfer.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py w68-token-freeze-bypass-transfer.yaml
Source: W6-8 zero-coverage detector batch (auditooor capability lift)
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class W68TokenFreezeBypassTransfer(AbstractDetector):
    ARGUMENT = "w68-token-freeze-bypass-transfer"
    HELP = "Token-holder restriction bypassed because transfer/execution/exit paths omit the frozen/blocked/vetoed registry check"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/w68-token-freeze-bypass-transfer.yaml"
    WIKI_TITLE = "Token-holder restriction bypassed by unrestricted transfer/execution/exit path"
    WIKI_DESCRIPTION = "The contract maintains a frozen/blocked/vetoed token-holder registry but a token-moving, token-executing, or exit-rights path does not consult it, so a restricted holder can still transfer, execute/join, move, burn, approve, ragequit, or exit."
    WIKI_EXPLOIT_SCENARIO = "Token-holder restriction bypassed because transfer/execution/exit paths omit the frozen/blocked/vetoed registry check"
    WIKI_RECOMMENDATION = "Require the restriction check in every token-holder action path: transfer, execute/join, move, burn, approve, ragequit, and exit."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(frozen|blocked|vetoed)'}]
    _MATCH = [{'function.name_matches': '(?i).*(transfer|send|move|burn|burnFrom|approve|setApprovalForAll|ragequit|leavePool|exitPool|redeem|execute|join|fork).*'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.body_contains_regex': '(?i)(balanceOf\\s*\\[[^\\]]+\\]\\s*(-=|\\+=)|(?:allowance|_allowances)\\s*\\[[^\\]]+\\]\\s*\\[[^\\]]+\\]\\s*=\\s*|shares\\s*\\[[^\\]]+\\]\\s*(-=|\\+=)|poolShares\\s*\\[[^\\]]+\\]\\s*(-=|\\+=)|memberShares\\s*\\[[^\\]]+\\]\\s*(-=|\\+=)|stakedBalance\\s*\\[[^\\]]+\\]\\s*(-=|\\+=)|_burn\\s*\\(|_approve\\s*\\(|approve\\s*\\(|transferFrom\\s*\\()'}, {'function.body_not_contains_regex': '(?i)(frozen|blocked|vetoed)'}]

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
                info = [f, f" - w68-token-freeze-bypass-transfer: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
