"""
quorum-threshold-setter-missing-live-bounds - generated from reference/patterns.dsl/quorum-threshold-setter-missing-live-bounds.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py quorum-threshold-setter-missing-live-bounds.yaml
Source: auditooor capability lift 2026-06-02 sibling generalizer
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class QuorumThresholdSetterMissingLiveBounds(AbstractDetector):
    ARGUMENT = "quorum-threshold-setter-missing-live-bounds"
    HELP = "Governance quorum or veto threshold setter writes a new threshold without validating it against the live member, supply, or voting-power denominator."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/quorum-threshold-setter-missing-live-bounds.yaml"
    WIKI_TITLE = "Quorum threshold setter missing live bounds"
    WIKI_DESCRIPTION = "A public governance setter stores a quorum, veto, threshold, denominator, votes, or power value without comparing it to a live denominator such as member count, total supply, or total voting power. The new value can drop quorum or veto protection below the intended floor."
    WIKI_EXPLOIT_SCENARIO = "Governance quorum or veto threshold setter writes a new threshold without validating it against the live member, supply, or voting-power denominator."
    WIKI_RECOMMENDATION = "Validate every quorum or veto threshold setter against live member, supply, or voting-power denominators before storing the value, and centralize bounds in a helper the setter always calls."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(govern|council|committee|member|quorum|threshold|veto|vote|power|denominator|supply)'}, {'contract.has_state_var_matching': '(?i)(members|memberCount|quorum|threshold|veto|vote|power|denominator|supply|totalPower|minVotes)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i).*(set|update|change|configure).*(quorum|threshold|veto|votes|power|denominator).*'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.is_mutating': True}, {'function.writes_storage_matching': '(?i)(quorum|threshold|veto|votes|power|denominator|minVotes|totalPower|eligibleVotes)'}, {'function.has_param_name_matching': '(?i)(quorum|threshold|votes|power|denominator|value|new)'}, {'function.not_body_contains_regex': '(?i)(require|assert)\\s*\\([^)]*(members?\\.length|memberCount|totalMembers|totalSupply|getPastTotalSupply|totalVotingPower|liveTotalSupply|MIN_QUORUM|MAX_QUORUM|MIN_VETO|MAX_VETO|MIN_VOTES|MAX_VOTES|bps|basis[_-]?points|WAD|1e18|SCALE)'}, {'function.does_not_call_matching_regex': '(?i)(check|validate|enforce|guard|bound|sync|refresh|recompute|normalize).*(quorum|threshold|votes|veto|power|denominator|member|supply)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" - quorum-threshold-setter-missing-live-bounds: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
