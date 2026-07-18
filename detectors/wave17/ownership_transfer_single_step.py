"""
ownership-transfer-single-step — generated from reference/patterns.dsl/ownership-transfer-single-step.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ownership-transfer-single-step.yaml
Source: solodit-cluster/C0253
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OwnershipTransferSingleStep(AbstractDetector):
    ARGUMENT = "ownership-transfer-single-step"
    HELP = "Privileged role-rotation setter (transferOwnership / setAdmin / setGuardian / setGovernance) writes the critical role slot in a single step without a pending-accept handshake. A fat-finger or malicious proposal can permanently lock the admin role at an unreachable address."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ownership-transfer-single-step.yaml"
    WIKI_TITLE = "Single-step ownership / admin / governance transfer without pending-accept handshake"
    WIKI_DESCRIPTION = "The contract holds a critical role slot (owner / admin / guardian / governance) that controls protocol configuration or fund routing, and exposes a setter that assigns the slot in one transaction. No sibling function (pendingOwner / acceptOwnership / pendingAdmin / acceptAdmin) implements a two-step accept handshake. A miskeyed transfer, a compromised multisig proposal, or an upstream key rotation"
    WIKI_EXPLOIT_SCENARIO = "Governance submits `transferOwnership(0xDEAD...)` to rotate the admin key, but the payload contains a typo. The setter writes `owner = 0xDEAD...` in one step. The attacker (or nobody) controls the new address. Every subsequent `onlyOwner` action reverts or is permanently redirected. For a token treasury this can freeze upgrades; for a CTF router or oracle-manager contract it can redirect every fut"
    WIKI_RECOMMENDATION = "Adopt a two-step handshake: have the current owner call `transferOwnership(newOwner)` to stage the value in `pendingOwner`, then require the incoming address to call `acceptOwnership()` from its own key to finalise the write. OpenZeppelin's `Ownable2Step` and `AccessControlDefaultAdminRules` ship th"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'owner|admin|guardian|governance'}, {'contract.has_no_function_body_matching': 'pendingOwner|pendingAdmin|acceptOwnership|acceptAdmin|_pendingOwner'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(transferOwnership|setOwner|setAdmin|setGuardian|setGovernance|changeOwner|_transferOwnership)$'}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyAdmin', 'onlyRoles', 'onlyGovernance', 'onlyRole', 'onlyGov', 'onlyTimelock'], 'negate': False}}, {'function.writes_storage_matching': 'owner|admin|guardian|governance'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — ownership-transfer-single-step: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
