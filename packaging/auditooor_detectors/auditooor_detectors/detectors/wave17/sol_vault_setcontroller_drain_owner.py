"""
sol-vault-setcontroller-drain-owner — generated from reference/patterns.dsl/sol-vault-setcontroller-drain-owner.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py sol-vault-setcontroller-drain-owner.yaml
Source: solodit-cluster-C0342-VaultController
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SolVaultSetcontrollerDrainOwner(AbstractDetector):
    ARGUMENT = "sol-vault-setcontroller-drain-owner"
    HELP = "`setController`/`setTreasury` immediately overwrites a privileged role with no timelock or two-step."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/sol-vault-setcontroller-drain-owner.yaml"
    WIKI_TITLE = "Vault setController has no timelock"
    WIKI_DESCRIPTION = "Controller/treasury/admin roles govern who can drain, pause, or reconfigure a vault. Immediate overwrite gives a compromised owner (or stolen key) one-step drain: `setController(attacker) -> controller.drain()`. A timelock or two-step pattern gives users time to exit."
    WIKI_EXPLOIT_SCENARIO = "C0342 H-09/H-10: `Vault.setController` allowed owner to instantly route new controller; a compromised multisig used it to set an attacker-controlled controller and drained in the same block."
    WIKI_RECOMMENDATION = "Use a two-step pattern: `setPendingController(newC)` + `acceptController()` after `MIN_DELAY`. Or gate behind the system timelock/governor."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'Vault|IController|setController|onlyController'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(setController|setAdmin|setTreasury|changeTreasury)$'}, {'function.writes_storage_matching': 'controller|admin|treasury'}, {'function.body_not_contains_regex': 'pendingController|_pendingController|timelock|queueController|scheduleController'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — sol-vault-setcontroller-drain-owner: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
