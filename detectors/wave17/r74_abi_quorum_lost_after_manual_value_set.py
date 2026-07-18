"""
r74-abi-quorum-lost-after-manual-value-set - generated from reference/patterns.dsl/r74-abi-quorum-lost-after-manual-value-set.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r74-abi-quorum-lost-after-manual-value-set.yaml
Source: r74b-cross-firm-tob+cs
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R74AbiQuorumLostAfterManualValueSet(AbstractDetector):
    ARGUMENT = "r74-abi-quorum-lost-after-manual-value-set"
    HELP = "Governance veto/quorum setter or config path directly writes quorum-like storage for a new threshold, denominator, or voting-power value without a visible live-denominator bound helper, allowing veto/quorum to fall below the intended floor."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r74-abi-quorum-lost-after-manual-value-set.yaml"
    WIKI_TITLE = "Governance veto/quorum setter or config path bypasses live-denominator bounds"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. This row currently proves only the narrow governance/veto setter or config path shape where a public `setQuorum`/`setThreshold`/`setVetoThreshold`/`setGovernanceConfig`-style entrypoint writes quorum-like storage without any visible live-denominator, snapshot, membership-count, or minimum-bounds validation in the same function. NOT_SUBMIT_READY."
    WIKI_EXPLOIT_SCENARIO = "A council has 7 members and veto threshold 4. A legitimate governance action calls `setVetoThreshold(2)`, `setQuorumDenominator(2500)`, or `setGovernanceConfig(...)`. Because the setter or config path only writes the new value and does not validate it against a live denominator, snapshot supply, or configured minimum floor, future proposals can be passed or vetoed with too few aligned votes."
    WIKI_RECOMMENDATION = "Validate veto/quorum setters and config paths against a live denominator before storing the new value, for example `require(newThreshold * 10_000 >= members.length * MIN_VETO_BPS, 'threshold too low');`. Keep the bound check in the setter or in a dedicated helper the setter always calls."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)\\b(Governor|Governance|Congress|Council|Committee|proposal|quorum|threshold|members|veto|guardian|challenge|dispute|optimistic|snapshot|power|denominator|supply|vote|config|params|settings|rules)\\b'}, {'contract.has_state_var_matching': '(?i)(quorum|threshold|minVotes|memberCount|members|veto|guardian|challenge|dispute|power|denominator|snapshot|supply|votingPower|totalPower|totalSupply|votes|config|params|settings|rules|floor|limit)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(set|update|change|configure|init|seed|_set|_configure)(Quorum|Threshold|VetoThreshold|VetoPower|VotingPower|QuorumDenominator|Denominator|MinVotes|Snapshot|PastSupply|TotalPower|GovernanceConfig|VotingConfig|VetoConfig|Parameters|Config|Floor|Limit)$'}, {'function.is_mutating': True}, {'function.writes_storage_matching': '(?i)(quorum|threshold|minVotes|veto|power|denominator|snapshot|supply|votingPower|totalPower|totalSupply|eligibleVotes|pastSupply|config|params|settings|rules|floor|limit)'}, {'function.has_param_name_matching': '(?i)(quorum|threshold|votes|power|denominator|snapshot|supply|value|config|params|settings|rules|floor|limit)'}, {'function.not_body_contains_regex': '(?i)(require|assert)\\s*\\([^)]*(members?\\.length|memberCount|totalMembers|totalSupply|getPastTotalSupply|totalVotingPower|liveTotalSupply|currentTotalSupply|MIN_QUORUM|MAX_QUORUM|MIN_VETO|MAX_VETO|quorumNumerator|quorumDenominator|MIN_VOTES|MAX_VOTES|bps|basis[_-]?points|WAD|1e18|SCALE|validate.*(quorum|threshold|veto|power|denominator|snapshot|config|params|settings))'}, {'function.does_not_call_matching_regex': '(?i)(check|validate|enforce|guard|bound|sync|refresh|accrue|recompute|normalize|restore).*(quorum|threshold|votes|veto|power|denominator|snapshot|config|params|settings)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" - r74-abi-quorum-lost-after-manual-value-set: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
