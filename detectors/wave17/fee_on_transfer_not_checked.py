"""
fee-on-transfer-not-checked — generated from reference/patterns.dsl/fee-on-transfer-not-checked.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fee-on-transfer-not-checked.yaml
Source: solodit/C0126
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FeeOnTransferNotChecked(AbstractDetector):
    ARGUMENT = "fee-on-transfer-not-checked"
    HELP = "transferFrom() result used in accounting without pre/post balanceOf(address(this)) check — breaks with fee-on-transfer tokens (USDT fee mode, PAXG, deflationary)."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fee-on-transfer-not-checked.yaml"
    WIKI_TITLE = "Fee-on-transfer token accounting discrepancy"
    WIKI_DESCRIPTION = "The contract invokes ERC20 transferFrom and uses the caller-supplied amount directly in state updates (mint / balance mapping / share calculation) without measuring the actual received amount via balanceOf(address(this)). Fee-on-transfer and deflationary tokens deliver strictly less than the specified amount, causing over-credit that can drain reserves."
    WIKI_EXPLOIT_SCENARIO = "Pool accepts a fee-on-transfer ERC20. User calls deposit(1_000e18). The token applies a 2% transfer fee, so the pool actually receives 980e18. The contract credits the depositor with 1_000e18 of shares / balance. Over time withdrawals drain the pool because booked balances exceed real holdings."
    WIKI_RECOMMENDATION = "Snapshot balanceOf(address(this)) before the transferFrom, call transferFrom, then credit `balanceAfter - balanceBefore` (not the passed amount). Alternatively reject fee-on-transfer tokens explicitly at the registry level."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': '(?s)^(?=(?:(?!balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\))(?!balanceOf\\s*\\([^)]*\\)\\s*-).)*$).*\\.transferFrom\\s*\\('}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fee-on-transfer-not-checked: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
