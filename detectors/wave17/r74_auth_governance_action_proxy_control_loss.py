"""
r74-auth-governance-action-proxy-control-loss — generated from reference/patterns.dsl/r74-auth-governance-action-proxy-control-loss.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r74-auth-governance-action-proxy-control-loss.yaml
Source: r74b-cross-firm-cs+oz
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R74AuthGovernanceActionProxyControlLoss(AbstractDetector):
    ARGUMENT = "r74-auth-governance-action-proxy-control-loss"
    HELP = "setOwner/setAuthority writes the new principal in one step without zero-address rejection or a pending-accept handshake; a mistyped address locks out governance forever."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r74-auth-governance-action-proxy-control-loss.yaml"
    WIKI_TITLE = "Single-step ownership transfer without zero-address rejection"
    WIKI_DESCRIPTION = "Privileged-role setters that overwrite the authority in one transaction and do not require the new address to accept the role (or even to be non-zero) allow governance to be permanently lost via a single typo, a lost private key for the new address, or a misconfigured multisig. On a proxy chain (govActionsProxy -> pauseProxy -> logic), losing authority at any link bricks every downstream contract,"
    WIKI_EXPLOIT_SCENARIO = "A DSR-style pause-proxy has an onlyAuthority modifier guarding setAuthority. Governance executes setAuthority(newMultisigAddress). The new multisig signs correctly on a testnet but its mainnet deployment was never actually created — the address is unowned. The pause-proxy now has an unreachable authority; the protocol's emergency-shutdown circuit breaker cannot be triggered, upgrade timelocks cann"
    WIKI_RECOMMENDATION = "Use two-step ownership (OpenZeppelin Ownable2Step pattern): pendingOwner = x; then newOwner must call acceptOwnership() from the pending address before it becomes active. Additionally, always reject address(0) in the setter: `require(newOwner != address(0), 'zero');`. For proxy-chain setups, require"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(owner|admin|governance|guardian|Proxy|authority|authorized|privileged|setAuthority)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(setOwner|transferOwnership|setAdmin|setAdminRole|setAuthority|setAuthorityAddress|setGovernance|setGovernor|setPendingOwner|setPendingAdmin|renounceOwnership|renounceRole|renounceAdmin|renounceGovernance|renounceAuthority|setAuthorized|setAuthorizedOperator|setMaster|setMasterAdmin|changeOwner|changeAdmin|changeAuthority)$'}, {'function.writes_storage_matching': '(owner|admin|authority|governance|master|guardian|_authorized)'}, {'function.body_not_contains_regex': 'pendingOwner|pendingAdmin|pendingAuthority|_pending|acceptOwnership|claimOwnership|setPending'}, {'function.body_not_contains_regex': 'require\\s*\\([^)]*!=\\s*address\\s*\\(\\s*0\\s*\\)|newOwner\\s*!=\\s*address\\(0\\)|_newAdmin\\s*!=\\s*address\\(0\\)|require\\s*\\(\\s*\\w+\\s*!=\\s*0x0'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r74-auth-governance-action-proxy-control-loss: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
