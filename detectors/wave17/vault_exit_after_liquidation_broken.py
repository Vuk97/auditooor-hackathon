"""
vault-exit-after-liquidation-broken — generated from reference/patterns.dsl/vault-exit-after-liquidation-broken.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py vault-exit-after-liquidation-broken.yaml
Source: solodit-cluster/C0352
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class VaultExitAfterLiquidationBroken(AbstractDetector):
    ARGUMENT = "vault-exit-after-liquidation-broken"
    HELP = "Vault exit/redeem subtracts debt or collateral from a position that was already debited by liquidation, double-subtracting and stranding the user."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/vault-exit-after-liquidation-broken.yaml"
    WIKI_TITLE = "Vault exit after liquidation double-subtracts debt/collateral, position stuck"
    WIKI_DESCRIPTION = "An external exit / redeem / withdrawMax path on a leveraged vault reads `position.debt` (or `loss`, `margin`, `collateral`) and subtracts it from the position's collateral without first consulting a post-liquidation adjustment flag. When liquidation previously reduced BOTH the collateral and debt sides of the same position, the exit path subtracts the already-reduced value a second time — the arit"
    WIKI_EXPLOIT_SCENARIO = "Alice deposits into a leveraged vault that tracks `position.collateral` and `position.debt`. A price move triggers a partial liquidation: the liquidator seizes collateral, repays part of the debt, and the vault decrements both `position.collateral` and `position.debt` in the same tx. Later Alice calls exit() to withdraw her remaining balance. The exit path computes `payout = position.collateral - "
    WIKI_RECOMMENDATION = "Track a per-position liquidation flag (`wasLiquidated`, `liquidationNonce`, `liquidationCount`) that the exit / redeem path consults before debiting debt or collateral a second time. Collapse liquidation bookkeeping and user-exit bookkeeping into a single state-delta helper so the subtraction happen"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'vault|position|leverage|collateral|debt'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'exit|redeem|withdrawMax|_exit|closePosition|cashOut|liquidateExit'}, {'function.body_contains_regex': {'regex': '\\.(debt|collateral|loss|margin)\\s*-=|\\.(debt|collateral|loss|margin)\\s*-\\s*'}}, {'function.body_not_contains_regex': 'wasLiquidated|liquidationNonce|liquidationCount|if\\s*\\(.*(liquidated|seized|slashed)\\s*\\)\\s*\\{|postLiquidationAdjust'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — vault-exit-after-liquidation-broken: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
