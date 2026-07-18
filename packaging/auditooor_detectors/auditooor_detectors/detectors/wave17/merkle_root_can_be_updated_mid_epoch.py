"""
merkle-root-can-be-updated-mid-epoch — generated from reference/patterns.dsl/merkle-root-can-be-updated-mid-epoch.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py merkle-root-can-be-updated-mid-epoch.yaml
Source: auditooor-round-34
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MerkleRootCanBeUpdatedMidEpoch(AbstractDetector):
    ARGUMENT = "merkle-root-can-be-updated-mid-epoch"
    HELP = "Admin setter can replace the merkle root at any time, invalidating in-flight user proofs or enabling targeted censorship of specific claimers."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/merkle-root-can-be-updated-mid-epoch.yaml"
    WIKI_TITLE = "Merkle root can be updated mid-epoch, invalidating in-flight claim proofs"
    WIKI_DESCRIPTION = "The contract exposes an admin-gated setter (setMerkleRoot / updateRoot / setClaimRoot / _setRoot / changeRoot) that overwrites the active merkle root with no timelock, no effective-after delay, and no freeze-after-publication flag. Users construct claim proofs off-chain against the currently-published root; if the admin replaces the root before their tx lands, every in-flight proof reverts on inva"
    WIKI_EXPLOIT_SCENARIO = "A distributor contract stores `merkleRoot` and honours `claim(uint256 amount, bytes32[] proof)`. Alice generates her proof from the current off-chain snapshot and broadcasts `claim(1000, proof_A)`. While her tx is pending, the admin calls `setMerkleRoot(newRoot)` where `newRoot` is the tree rebuilt with Alice's leaf removed. Alice's tx lands after the setter and reverts on invalid-proof. Her entit"
    WIKI_RECOMMENDATION = "Gate root rotation behind one of: (a) a timelock delay (OpenZeppelin TimelockController) so a new root is only effective N hours after scheduling, giving in-flight proofs a deterministic deadline; (b) an explicit epoch model where each epoch's root is frozen and a new slot/root is required per epoch"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'merkleRoot|root|claimRoot'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'setMerkleRoot|updateRoot|setClaimRoot|_setRoot|changeRoot'}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyAdmin', 'onlyRoles', 'onlyGovernance'], 'negate': False}}, {'function.writes_storage_matching': 'merkleRoot|root|claimRoot'}, {'function.body_not_contains_regex': 'timelock|_timelock|effectiveAfter|scheduleUpdate|rootFrozen|require\\s*\\(.*block\\.timestamp\\s*<=?\\s*\\w*(deadline|epoch|window)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — merkle-root-can-be-updated-mid-epoch: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
