"""
bribe-reward-grief-permissionless-poke — generated from reference/patterns.dsl/bribe-reward-grief-permissionless-poke.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bribe-reward-grief-permissionless-poke.yaml
Source: solodit-cluster/C0263
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BribeRewardGriefPermissionlessPoke(AbstractDetector):
    ARGUMENT = "bribe-reward-grief-permissionless-poke"
    HELP = "Permissionless poke/updateBribe/claimBribe/syncBribe on a bribe-voter gauge mutates bribe/reward/lastUpdate storage and retires pending rewards for the prior voter without compensation — any caller can grief other voters by calling poke(victim)."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bribe-reward-grief-permissionless-poke.yaml"
    WIKI_TITLE = "Bribe reward griefing via permissionless Voter.poke"
    WIKI_DESCRIPTION = "Velodrome/Solidly-style voting gauges pair each voter with a bribe contract that tracks earnings on a per-epoch reward index. The Voter.poke (and sibling updateBribe / claimBribe / syncBribe) functions rebuild the bribe reward index for a given tokenId. When these functions are callable by anyone and the update logic resets pending rewards of the prior voter without crediting or snapshotting them,"
    WIKI_EXPLOIT_SCENARIO = "Alice votes for gauge G during epoch E and accrues bribe rewards proportional to her voting power. Before the epoch closes, attacker Mallory calls Voter.poke(alice.tokenId). poke() invokes the bribe contract's internal update routine, which snapshots Alice's voting weight to zero / to the new (post-poke) value and advances lastUpdate[G][E] past Alice's claim horizon. Alice's pending bribe token ac"
    WIKI_RECOMMENDATION = "Gate poke / updateBribe / claimBribe / syncBribe behind either (a) a `onlyVoter` / `onlyGauge` / `onlyOwner` access modifier, (b) a `msg.sender == voterOf(tokenId)` require, or (c) an explicit pull-only claim pattern where the bribe-update routine snapshots the outgoing voter's share of the reward i"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(bribe|reward|voter|epoch|gauge)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(poke|updateBribe|_poke|_updateBribe|claimBribe|syncBribe)$'}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyAdmin', 'onlyRoles', 'onlyVoter', 'onlyGovernor', 'onlyGauge'], 'negate': True}}, {'function.writes_storage_matching': '(bribe|reward|lastUpdate)'}, {'function.is_mutating': True}, {'function.not_slither_synthetic': True}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — bribe-reward-grief-permissionless-poke: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
