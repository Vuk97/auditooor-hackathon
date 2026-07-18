"""
glider-accounting-updates-not-assuming-fee-on-transfers — generated from reference/patterns.dsl/glider-accounting-updates-not-assuming-fee-on-transfers.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-accounting-updates-not-assuming-fee-on-transfers.yaml
Source: hexens-glider/accounting-updates-not-assuming-fee-on-transfers
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderAccountingUpdatesNotAssumingFeeOnTransfers(AbstractDetector):
    ARGUMENT = "glider-accounting-updates-not-assuming-fee-on-transfers"
    HELP = "accounting-updates-not-assuming-fee-on-transfers"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-accounting-updates-not-assuming-fee-on-transfers.yaml"
    WIKI_TITLE = "accounting-updates-not-assuming-fee-on-transfers"
    WIKI_DESCRIPTION = "accounting-updates-not-assuming-fee-on-transfers"
    WIKI_EXPLOIT_SCENARIO = "Transpiled from Hexens Glider query accounting-updates-not-assuming-fee-on-transfers. Tags: ."
    WIKI_RECOMMENDATION = "Apply the check implied by the original Glider query — see hexens-glider source for context."

    _PRECONDITIONS = [{'function.kind': 'external'}, {'function.kind': 'external_or_public'}, {'contract.source_matches_regex': '(Vault|Pool|Deposit|Strategy|ERC4626|deposit|supply|stake|handleDeposit|FeeOnTransfer|rebase)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(deposit|depositFor|supply|stake|mint|addLiquidity|provide|contribute|lend|fund)\\w*$'}, {'function.body_contains_regex': '(?:safeTransferFrom|transferFrom)\\s*\\('}, {'function.body_contains_regex': '(?:totalAssets|totalSupply|balances\\[|deposits\\[|shares\\[|reserves|_mint)\\s*(?:\\+=|=\\s*[^;]*\\+\\s*|\\[\\s*\\w+\\s*\\]\\s*\\+=|\\()'}, {'function.body_not_contains_regex': '(?i)(balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\)\\s*-\\s*balance|received\\s*=\\s*balanceOf|bal(?:ance)?After\\s*-\\s*bal(?:ance)?Before|delta\\s*=\\s*.*balanceOf|IERC20\\s*\\(\\s*\\w+\\s*\\)\\.balanceOf\\s*\\(\\s*address\\s*\\(\\s*this)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)(view\\s+returns|pure\\s+returns|internal\\s+view|internal\\s+pure|balanceBefore|balanceAfter|amountReceived\\s*=\\s*|_safeTransferFromAndMeasure|isFeeOnTransfer\\s*\\()'}]

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
                info = [f, f" — glider-accounting-updates-not-assuming-fee-on-transfers: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
