"""
rd-rounding-direction-zero-payout-after-balance-debit - generated from reference/patterns.dsl/rd-rounding-direction-zero-payout-after-balance-debit.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py rd-rounding-direction-zero-payout-after-balance-debit.yaml
Source: detector-lift-fire4-rwrq-rounding-direction-attack-abb2bb9e3ead
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RdRoundingDirectionZeroPayoutAfterBalanceDebit(AbstractDetector):
    ARGUMENT = "rd-rounding-direction-zero-payout-after-balance-debit"
    HELP = "Exit path debits a user balance, then computes a 1e12 downscaled payout with floor division and transfers that rounded value without a zero-payout guard."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/rd-rounding-direction-zero-payout-after-balance-debit.yaml"
    WIKI_TITLE = "Decimal downscale floors payout after balance debit"
    WIKI_DESCRIPTION = "A withdraw, redeem, claim, or payout path mutates user accounting before computing a token payout as `x / 1e12`. For sub-1e12 internal balances the payout rounds down to zero, but the user balance has already been debited and the transfer still executes with the zero-valued local."
    WIKI_EXPLOIT_SCENARIO = "A vault stores user balances in 18-decimal precision and pays a 6-decimal token. The withdraw path first subtracts `amount18` from the user's balance, then computes `payout6 = amount18 / 1e12`, and then transfers `payout6`. For `amount18 < 1e12`, the transfer amount is zero while the user's internal balance is cleared."
    WIKI_RECOMMENDATION = "Compute the rounded payout before mutating user accounting, reject zero payouts with `require(payout > 0)`, or apply a documented ceil-rounding path such as `Math.ceilDiv(x, 1e12)` when the protocol intends every non-zero internal amount to map to an external token unit."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(1e12|scaleDown|downscale|toE6|to6Decimals|USDC|USDT)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(withdraw|redeem|claim|exit|settle|payout|cashOut)$'}, {'function.body_ordered_regex': {'first': '(?i)(?:balance|balances|share|shares|credit|credits|accounting|position)\\w*\\s*\\[[^\\]]+\\]\\s*(?:-=|=)', 'second': '(?i)(?:payout|amount|assets|tokens)\\w*\\s*=\\s*[^;]+/\\s*1e12\\b', 'ignore_comments_and_strings': True}}, {'function.body_contains_regex': '\\b([A-Za-z_][A-Za-z0-9_]*)\\s*=\\s*[^;]+/\\s*1e12\\b[\\s\\S]{0,400}(?:safeTransfer|\\.transfer)\\s*\\([^;]*\\b\\1\\b'}, {'function.body_not_contains_regex': '(?i)(ceilDiv|Math\\.ceilDiv|mulDivRoundingUp|mulDivUp|roundUp|Rounding\\.(Up|Ceil)|\\+\\s*1e12\\s*-\\s*1|require\\s*\\([^;]*(?:payout|amount|assets|tokens)\\w*\\s*(?:>\\s*0|>=\\s*1|!=\\s*0)|if\\s*\\([^)]*(?:payout|amount|assets|tokens)\\w*\\s*==\\s*0\\s*\\)\\s*(?:revert|return)|ZeroAmount|ZeroAssets|ZeroPayout|InsufficientOutput)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture|harness)\\b'}]

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
                info = [f, f" - rd-rounding-direction-zero-payout-after-balance-debit: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
