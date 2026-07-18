"""
governance-offboard-flag-not-cleared-on-onboard — generated from reference/patterns.dsl/governance-offboard-flag-not-cleared-on-onboard.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py governance-offboard-flag-not-cleared-on-onboard.yaml
Source: lisa-mine-r99-case-05427-c4-eth-credit-guild-2023-12
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GovernanceOffboardFlagNotClearedOnOnboard(AbstractDetector):
    ARGUMENT = "governance-offboard-flag-not-cleared-on-onboard"
    HELP = "Governance contract has a `canOffboard[term]` (or `canRemove`, `toBeRemoved`) mapping flipped to true once an offboard poll reaches quorum, and a separate `cleanup()` path that resets the flag — but the flag is NOT reset by the `onboard` / `reOnboard` / `enableTerm` path. After offboard-quorum is re"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/governance-offboard-flag-not-cleared-on-onboard.yaml"
    WIKI_TITLE = "Governance onboard path does not clear stale `canOffboard` flag"
    WIKI_DESCRIPTION = "Pattern fires on governance/registry contracts that expose an `onboard` (or `reOnboard`, `proposeOnboard`, `enableTerm`) entry point and maintain a `canOffboard[term]` style mapping marking terms as offboard-eligible. When the onboard path lacks a `delete canOffboard[term]` / `canOffboard[term] = false` clear, a previously-quorum-approved offboard flag survives the re-onboarding. Anyone can then c"
    WIKI_EXPLOIT_SCENARIO = "ETH Credit Guild offboards a lending term via the standard 7-day poll; quorum reached; `canOffboard[term] = true`. The DAO accepts a community proposal to fix the term's risk params and re-onboards via timelocked `proposeOnboard`. The re-onboard path does not call `delete canOffboard[term]`. An attacker (no guild token required) calls `offboard(term)` the same block — flag is still true — and the "
    WIKI_RECOMMENDATION = "In the onboard / re-onboard / enableTerm function, immediately reset the offboard flag: `delete canOffboard[term];` (or `canOffboard[term] = false;`). Equivalently, gate the `offboard()` action on a fresh poll-block recency check — `require(canOffboardSetAt[term] >= termOnboardedAt[term])`. Add a fo"

    _PRECONDITIONS = [{'contract.has_state_var_matching': 'canOffboard|canRemove|toBeRemoved|markedForOffboard'}, {'contract.has_function_matching': 'onboard|reOnboard|proposeOnboard|allowImplementation'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(onboard|reOnboard|proposeOnboard|allowImplementation|enableTerm|registerTerm)$'}, {'function.body_not_contains_regex': '\\bdelete\\s+canOffboard|canOffboard\\s*\\[[^\\]]+\\]\\s*=\\s*false|canRemove\\s*\\[[^\\]]+\\]\\s*=\\s*false|delete\\s+canRemove|delete\\s+toBeRemoved|toBeRemoved\\s*\\[[^\\]]+\\]\\s*=\\s*false'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" — governance-offboard-flag-not-cleared-on-onboard: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
