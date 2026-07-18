"""
imm-selfdestruct-hook-skip-zero-amount-accrual — generated from reference/patterns.dsl/imm-selfdestruct-hook-skip-zero-amount-accrual.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py imm-selfdestruct-hook-skip-zero-amount-accrual.yaml
Source: immunefi/vechainthor-vtho-accrual-bypass
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ImmSelfdestructHookSkipZeroAmountAccrual(AbstractDetector):
    ARGUMENT = "imm-selfdestruct-hook-skip-zero-amount-accrual"
    HELP = "Pre-destroy / accrual-settlement hook skips its internal index update when `amount == 0`. Attacker triggers selfdestruct at the exact moment accrued==0 to avoid updating lastIndex, then farms fresh emissions at a new contract."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/imm-selfdestruct-hook-skip-zero-amount-accrual.yaml"
    WIKI_TITLE = "onDestroy / beforeSelfDestruct skips index update when amount == 0 (VeChainThor VTHO pattern)"
    WIKI_DESCRIPTION = "Rebasing / emission-accruing contracts often settle pending rewards in a `beforeSelfDestruct` / `onDestroy` hook. The hook pattern `if (pending != 0) { settle(pending); lastIndex = currentIndex; }` has a subtle defect: when `pending == 0` the `lastIndex` bookmark is not updated either. On VeChainThor this let an attacker flash-loan, trigger `OnSuicideContract` with zero accrued VTHO (by timing it "
    WIKI_EXPLOIT_SCENARIO = "VeChainThor (Dec 2024): attacker flash-loans VET, deploys a contract, waits 0 seconds, calls selfdestruct. `OnSuicideContract` reads `amount = accrued(contract, now)` = 0, skips the `SetEnergy` call entirely, destroys the contract. Attacker redeploys at a deterministic address using CREATE2, flash-loans again, repeats. Because the emission clock never resets but the suicide lets them sidestep the "
    WIKI_RECOMMENDATION = "Move the index / timestamp bookmark update OUT of the `if (amount != 0)` branch. The bookkeeping `lastIndex = currentIndex` (or `lastAccruedAt = block.timestamp`) must execute unconditionally on every destroy/touch, even when the settled amount is zero. Prefer a single `_accrue()` helper called at t"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'onDestroy|beforeSelfDestruct|_beforeSuicide|_preDestroy|selfdestruct\\s*\\(|_settleAccrual|_accrue'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '^(onDestroy|_beforeSuicide|beforeSelfDestruct|_preDestroy|onSuicideContract)$'}, {'function.body_contains_regex': '(amount|accrued|pending|energy)\\s*(!=|>)\\s*0|(amount|accrued|pending|energy)\\.Sign\\s*\\(\\s*\\)\\s*!=\\s*0'}, {'function.body_not_contains_regex': '_lastAccrued\\s*=\\s*block\\.timestamp|accrualTimestamp\\s*=\\s*block\\.timestamp|lastIndex\\s*=\\s*currentIndex'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — imm-selfdestruct-hook-skip-zero-amount-accrual: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
