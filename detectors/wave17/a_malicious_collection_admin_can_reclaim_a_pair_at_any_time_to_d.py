"""
a-malicious-collection-admin-can-reclaim-a-pair-at-any-time-to-d — generated from reference/patterns.dsl/a-malicious-collection-admin-can-reclaim-a-pair-at-any-time-to-d.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-malicious-collection-admin-can-reclaim-a-pair-at-any-time-to-d.yaml
Source: spearbit/Sudoswap-LSSVM2-Solodit-18301
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AMaliciousCollectionAdminCanReclaimAPairAtAnyTimeToD(AbstractDetector):
    ARGUMENT = "a-malicious-collection-admin-can-reclaim-a-pair-at-any-time-to-d"
    HELP = "A malicious collection admin can reclaim a pair at any time to deny enhanced setting royalties"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-malicious-collection-admin-can-reclaim-a-pair-at-any-time-to-d.yaml"
    WIKI_TITLE = "A malicious collection admin can reclaim a pair at any time to deny enhanced setting royalties"
    WIKI_DESCRIPTION = "## Security Report\n\n## Severity\n**Medium Risk**\n\n## Context\n`StandardSettings.sol#L164-L178`\n\n## Description\nA collection admin can forcibly/selectively call `reclaimPair()` prematurely (before the advertised and agreed upon lockup period) to unilaterally break the settings contract at any time. Thi"
    WIKI_EXPLOIT_SCENARIO = "Per Solodit #18301: ## Security Report\n\n## Severity\n**Medium Risk**\n\n## Context\n`StandardSettings.sol#L164-L178`\n\n## Description\nA collection admin can forcibly/selectively call `reclaimPair()` prematurely (before the ad"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '(?i)reclaimPair'}, {'contract.has_state_var_matching': '(?i)(unlock|lockup|cooldown|reclaimDelay|reclaimAfter|gracePeriod)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^reclaimPair$'}, {'function.body_contains_regex': '(?i)(authAllowedForToken|only[A-Za-z]*Admin|onlyOwner|onlyRole|collectionAdmin|isAdmin)'}, {'function.body_not_contains_regex': '(?i)(block\\.timestamp\\s*[<>]=?|unlockTime|lockup|cooldown|reclaimDelay|reclaimAfter|gracePeriod|timelock|deadline|waitPeriod)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" — a-malicious-collection-admin-can-reclaim-a-pair-at-any-time-to-d: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
