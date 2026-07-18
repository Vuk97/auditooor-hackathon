"""
vault-controller-setter-no-validation — generated from reference/patterns.dsl/vault-controller-setter-no-validation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py vault-controller-setter-no-validation.yaml
Source: solodit-cluster/C0313
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class VaultControllerSetterNoValidation(AbstractDetector):
    ARGUMENT = "vault-controller-setter-no-validation"
    HELP = "Privileged setter for a critical contract address (Controller/Treasury/Oracle/FeeReceiver/Admin/Guardian/PriceSource/Vault/Router/Strategy) writes the new address with neither a zero-address validation nor a two-step accept handshake. A single owner-key fat-finger can brick the protocol wiring or ro"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/vault-controller-setter-no-validation.yaml"
    WIKI_TITLE = "Vault / controller setter missing zero-address or two-step validation"
    WIKI_DESCRIPTION = "A privileged setter (onlyOwner / onlyAdmin / onlyRole) updates a contract-address state variable that governs critical protocol wiring — the vault controller, treasury receiver, oracle feed, price source, fee receiver, or strategy router. The setter neither rejects `address(0)` nor routes through a two-step `pending -> accept` handshake, so a single miskeyed transaction (or compromised multisig pr"
    WIKI_EXPLOIT_SCENARIO = "Governance submits `setController(0x0)` to rotate the controller but pastes an empty input. The setter writes `controller = address(0)` without validation. Every subsequent vault interaction that forwards through `controller` reverts or silently succeeds against the zero address, freezing deposits and making withdrawals impossible. Or: governance submits `setTreasury(attacker)`; funds accrue to th"
    WIKI_RECOMMENDATION = "Require `newAddr != address(0)` at the top of every critical-address setter. For addresses that control funds routing (treasury / fee receiver / controller), adopt a two-step handshake: the setter stages the value in `pendingX` and a separate `acceptX()` call from the incoming address finalises the "

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^set[A-Z][A-Za-z0-9_]*(Controller|Treasury|Oracle|FeeReceiver|FeeRecipient|Admin|Guardian|PriceSource|PriceFeed|Vault|Router|Strategy|StrategyManager)$'}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyAdmin', 'onlyRole', 'onlyRoles', 'onlyGovernance', 'onlyGov', 'onlyTimelock', 'onlyManager'], 'negate': False}}, {'function.body_not_contains_regex': 'require\\s*\\([^;]*!=\\s*address\\s*\\(\\s*0\\s*\\)|if\\s*\\([^;]*==\\s*address\\s*\\(\\s*0\\s*\\)\\s*\\)\\s*(revert|throw)|\\.notZero\\s*\\(|ZeroAddress\\s*\\(\\s*\\)|AddressZero\\s*\\(\\s*\\)|pendingController|acceptController|acceptOwnership|_pendingOwner'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — vault-controller-setter-no-validation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
