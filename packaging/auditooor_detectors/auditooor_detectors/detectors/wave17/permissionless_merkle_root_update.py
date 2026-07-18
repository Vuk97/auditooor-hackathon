"""
permissionless-merkle-root-update — generated from reference/patterns.dsl/permissionless-merkle-root-update.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py permissionless-merkle-root-update.yaml
Source: DeFiHackLabs/SuperRare (2025-07, $730K) — attacker called updateMerkleRoot on a staking proxy with no access gate, then claimed the entire staking-contract balance via an empty proof
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PermissionlessMerkleRootUpdate(AbstractDetector):
    ARGUMENT = "permissionless-merkle-root-update"
    HELP = "External updateMerkleRoot / setClaimRoot has no admin gate. Any caller can replace the root and claim the full distribution balance."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/permissionless-merkle-root-update.yaml"
    WIKI_TITLE = "Permissionless merkle-root setter allows full airdrop drain"
    WIKI_DESCRIPTION = "A contract that gates token distributions by a stored merkleRoot exposes an external setter — updateMerkleRoot / setClaimRoot / setMerkleRoot — without any onlyOwner / onlyRole / msg.sender check. Because the claim function verifies claimant+amount leaves against this root, an attacker can overwrite the root with one whose leaves include (attacker, totalBalance), then call claim() with a matching "
    WIKI_EXPLOIT_SCENARIO = "SuperRare staking proxy (2025-07, $730K loss). The proxy exposed `updateMerkleRoot(bytes32 newRoot) external` with no modifier. Attacker computed a root for the leaf (attacker, 11907874713019104529057960) — the full RARE balance parked in the staking contract — then called updateMerkleRoot(fakeRoot) and claim(fullBalance, emptyProof). The claim verified against the attacker-controlled root and tra"
    WIKI_RECOMMENDATION = "Gate every merkleRoot setter with onlyOwner / onlyRole(DISTRIBUTOR_ROLE) / a timelock-controlled governance modifier. For permissionless distribution systems, add an epoch + monotonic-version check that prevents re-rooting a live epoch, so a stale root cannot be replaced with an attacker-chosen one "

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'merkleRoot|claimRoot|rewardRoot|airdropRoot|distributionRoot'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(set|update|change|rotate)(Merkle|Claim|Reward|Airdrop|Distribution)?Root$|^setMerkleRoot$|^updateMerkleRoot$|^updateClaimRoot$'}, {'function.writes_storage_matching': 'merkleRoot|claimRoot|rewardRoot|airdropRoot|distributionRoot'}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyAdmin', 'onlyRole', 'onlyRoles', 'onlyGovernance', 'onlyDistributor', 'auth'], 'negate': True}}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*msg\\.sender\\s*==\\s*(owner|admin|governance|distributor)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — permissionless-merkle-root-update: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
