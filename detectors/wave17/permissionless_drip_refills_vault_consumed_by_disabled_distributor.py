"""
permissionless-drip-refills-vault-consumed-by-disabled-distributor — generated from reference/patterns.dsl/permissionless-drip-refills-vault-consumed-by-disabled-distributor.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py permissionless-drip-refills-vault-consumed-by-disabled-distributor.yaml
Source: auditooor-R76-rekt-compound-2021
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PermissionlessDripRefillsVaultConsumedByDisabledDistributor(AbstractDetector):
    ARGUMENT = "permissionless-drip-refills-vault-consumed-by-disabled-distributor"
    HELP = "A permissionless `drip()` that pushes rewards from reservoir to distributor has no check on distributor health / pause state. If the distributor is known to be buggy, anyone can call drip to refill the attack surface indefinitely."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/permissionless-drip-refills-vault-consumed-by-disabled-distributor.yaml"
    WIKI_TITLE = "Permissionless reservoir drip has no circuit-breaker on downstream distributor"
    WIKI_DESCRIPTION = "Reservoir-style reward distribution uses a periodic `drip()` function that anyone can call to push accumulated rewards into a downstream Comptroller / MerkleDistributor / VestingVault. If the drip function never reads the distributor's health (paused, emergency, `badDistribution` flag), a bug in the downstream distribution math cannot be contained — anyone can refill the drain. Compound's post-Pro"
    WIKI_EXPLOIT_SCENARIO = "Comptroller ships Proposal 062 which has a bug that over-computes `compSpeeds` for certain markets, paying out inflated rewards on `claimComp`. Governance rolls Proposal 064 to disable the buggy code but does not pause Reservoir. Reservoir accumulates 0.5 COMP/block. Any user calls `Reservoir.drip()` to push fresh COMP into the broken Comptroller. Attacker calls `claimComp()` and walks away with 6"
    WIKI_RECOMMENDATION = "Add a `paused()` / `sanityCheck()` hook on the drip path that queries the downstream distributor and reverts if it is in an emergency / known-broken state. Alternatively, make `drip` permissioned (only callable by governance or a watchdog keeper) so that it can be withheld while investigating. Expos"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, 'Contract exposes a permissionless `drip`/`refill`/`topUp` function that transfers tokens to a downstream distributor/comptroller.']
    _MATCH = [{'function.kind': 'external'}, {'function.name_matches': '(?i)^drip$|^drip\\w|refill|topUp|replenish|feed\\w*Reserve|streamTo'}, {'function.body_contains_regex': '(?i)safeTransfer|transfer\\s*\\(\\s*target|IERC20\\([^)]*\\)\\.transfer'}, {'function.body_not_contains_regex': '(?i)pause|paused\\(\\)|emergencyStop|circuitBreaker|isDistributorHealthy|onlyComptrollerLive|sanityCheck|target\\.paused'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — permissionless-drip-refills-vault-consumed-by-disabled-distributor: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
