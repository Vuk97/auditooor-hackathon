"""
a-malicious-user-can-in-ate-his-voting-power-via-merge — generated from reference/patterns.dsl/a-malicious-user-can-in-ate-his-voting-power-via-merge.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-malicious-user-can-in-ate-his-voting-power-via-merge.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AMaliciousUserCanInAteHisVotingPowerViaMerge(AbstractDetector):
    ARGUMENT = "a-malicious-user-can-in-ate-his-voting-power-via-merge"
    HELP = "A malicious user can inflate his voting power via merge(): function reads balance/merge/tokenId state but does not call an accrue/update/sync/validate/check/refresh guard."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-malicious-user-can-in-ate-his-voting-power-via-merge.yaml"
    WIKI_TITLE = "A malicious user can inflate his voting power via merge()"
    WIKI_DESCRIPTION = "## Vulnerability in ZeroLocker.sol - Merge Function Exploit\n\n## Context\nZeroLocker.sol#L711\n\n## Description\nThe `merge` function in the ZeroLocker contract allows users to consolidate their stakes by merging multiple NFTs into one. However, this function can be exploited to artificially inflate the"
    WIKI_EXPLOIT_SCENARIO = "Per Solodit #40818: ## Vulnerability in ZeroLocker.sol - Merge Function Exploit\n\n## Context\nZeroLocker.sol#L711\n\n## Description\nThe `merge` function in the ZeroLocker contract allows users to consolidate their stakes by"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches': '(?i).*(merge|balanceOfNFT|tokenId|zeroToken).*'}, {'function.not_leaf_helper': True}, {'function.reads_state_var_matching_regex': '(?i).*(balanceOfNFT|merge|tokenId).*'}, {'function.calls_function_matching': {'regex': '(?i).*(accrue|update|sync|validate|check|refresh).*', 'negate': True}}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — a-malicious-user-can-in-ate-his-voting-power-via-merge: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
