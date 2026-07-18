"""
restriction-list-enforcement-bypass-internal-transfer — generated from reference/patterns.dsl/restriction-list-enforcement-bypass-internal-transfer.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py restriction-list-enforcement-bypass-internal-transfer.yaml
Source: solodit-cluster-C0141-variant
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RestrictionListEnforcementBypassInternalTransfer(AbstractDetector):
    ARGUMENT = "restriction-list-enforcement-bypass-internal-transfer"
    HELP = "Internal balance-moving helper (_transfer / _move / _batchTransfer / _migrateBalance / _adminTransfer / _forceTransfer) on a restriction-list-bearing token writes balances directly without consulting the same blacklist / restricted / frozen / whitelist guard that the external transfer path enforces."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/restriction-list-enforcement-bypass-internal-transfer.yaml"
    WIKI_TITLE = "Restriction-list bypass via internal transfer helper"
    WIKI_DESCRIPTION = "The contract maintains a blacklist / restricted / frozen / whitelist state variable and enforces it on the external `transfer` / `transferFrom` surface, but an internal balance-moving helper (`_transfer`, `_move`, `_batchTransfer`, `_migrateBalance`, `_adminTransfer`, `_forceTransfer`) writes the balance mapping directly without re-checking the list. Any trusted entry point that funnels through th"
    WIKI_EXPLOIT_SCENARIO = "Compliance tooling marks address B as restricted. The external `transfer` path correctly reverts on any call involving B. However, the protocol's airdrop helper calls `_batchTransfer(recipients, amounts)` to mass-distribute rewards; because `_batchTransfer` writes `balances[to] += amount` without consulting the restriction mapping, B receives fresh tokens that the compliance layer was supposed to "
    WIKI_RECOMMENDATION = "Every internal balance-moving helper MUST funnel through the same guard the external path uses — either by calling a shared `_beforeTokenTransfer(from, to, amount)` hook that enforces the restriction list, or by applying a `notRestricted(from, to)` modifier. Audits that follow the OpenZeppelin `_upd"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'blacklist|restricted|banned|frozen|whitelist'}]
    _MATCH = [{'function.kind': 'internal'}, {'function.name_matches': '^(_transfer|_move|_batchTransfer|_migrateBalance|_adminTransfer|_forceTransfer)$'}, {'function.writes_storage_matching': 'balances?|_balances'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*!\\s*blacklist|require\\s*\\(\\s*!\\s*restricted|require\\s*\\(\\s*!\\s*frozen|require\\s*\\(\\s*!\\s*banned|isBlacklisted\\s*\\(|isRestricted\\s*\\(|isFrozen\\s*\\(|isBanned\\s*\\(|_notRestricted|_checkBlacklist|_checkRestriction'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — restriction-list-enforcement-bypass-internal-transfer: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
