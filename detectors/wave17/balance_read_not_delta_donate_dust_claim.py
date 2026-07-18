"""
balance-read-not-delta-donate-dust-claim — generated from reference/patterns.dsl/balance-read-not-delta-donate-dust-claim.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py balance-read-not-delta-donate-dust-claim.yaml
Source: auditooor-R53-polymarket-adapter-dust-claim
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BalanceReadNotDeltaDonateDustClaim(AbstractDetector):
    ARGUMENT = "balance-read-not-delta-donate-dust-claim"
    HELP = "Function reads balanceOf(address(this)) after an inner adapter/DEX call and forwards the entire balance to msg.sender. No pre-call snapshot or delta subtraction, so any pre-existing donated balance is claimed by the first caller as their own output."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/balance-read-not-delta-donate-dust-claim.yaml"
    WIKI_TITLE = "Adapter claims donated / stranded balance via full balanceOf() forward"
    WIKI_DESCRIPTION = "After performing an inner adapter / DEX / swap / wrap call, the function reads the contract's total balance of an output token (`IERC20(TOKEN).balanceOf(address(this))`) and transfers or wraps that entire balance to `msg.sender` / a caller-supplied recipient. There is no pre-call snapshot (no `balanceBefore = balanceOf(this)` before the inner call) and no delta subtraction, so whatever pre-existin"
    WIKI_EXPLOIT_SCENARIO = "Adapter V2 wraps the legacy adapter's NO→YES conversion. After the inner `legacyAdapter.convertPositions(...)` returns, the V2 wrapper reads `USDCE.balanceOf(address(this))` and wraps the full balance to `msg.sender` as PMCT. An attacker donates 100 USDCE to the adapter (plain ERC20 transfer). Next honest caller of `convertPositions` receives 100 PMCT on top of their own legitimate conversion outp"
    WIKI_RECOMMENDATION = "Snapshot the balance before the inner call and only forward the delta:\n\n```solidity\nuint256 balanceBefore = IERC20(TOKEN).balanceOf(address(this));\nadapter.convertPositions(...);\nuint256 delta = IERC20(TOKEN).balanceOf(address(this)) - balanceBefore;\nif (delta > 0) { IERC20(TOKEN).safeTransfer"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_external_call': True}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': 'balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\)'}, {'function.body_contains_regex': '(safeTransfer|transfer|wrap|_to\\s*:\\s*msg\\.sender)\\s*\\(.*(msg\\.sender|_to|recipient|receiver)'}, {'function.body_not_contains_regex': '(balanceBefore|preBalance|oldBalance|snapshotBefore|balancePrior|startingBalance)'}, {'function.name_matches': 'convert|redeem|claim|unwrap|exchange|swap|migrate|convertPositions|redeemPositions'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — balance-read-not-delta-donate-dust-claim: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
