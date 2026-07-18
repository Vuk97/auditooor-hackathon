"""
withdraw-queue-amount-frozen-at-request-time — generated from reference/patterns.dsl/withdraw-queue-amount-frozen-at-request-time.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py withdraw-queue-amount-frozen-at-request-time.yaml
Source: auditooor-R75-c4-yield-2024-04-renzo-326
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class WithdrawQueueAmountFrozenAtRequestTime(AbstractDetector):
    ARGUMENT = "withdraw-queue-amount-frozen-at-request-time"
    HELP = "Withdraw amount is locked at request time using current TVL/oracle; claim later pays stale amount regardless of subsequent price moves."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/withdraw-queue-amount-frozen-at-request-time.yaml"
    WIKI_TITLE = "Cooldown-queue vault freezes asset payout at request time, enabling sandwich of TVL changes"
    WIKI_DESCRIPTION = "A multi-asset LST / yield vault that burns shares on request but delays the asset payout for a cooldown period evaluates the asset amount to redeem once — at request time — using the current oracle TVL. Because the payout is fully pinned, any positive or negative move of TVL, oracle price, or reward accrual between request and claim is transferred to whoever happens to be in the queue. A well-info"
    WIKI_EXPLOIT_SCENARIO = "Renzo WithdrawQueue: TVL rises by 1% at an oracle heartbeat. Attacker front-runs with deposit(stETH, 100 ETH), receives ezETH at old rate, then calls withdraw(asset=ETH) which pins amountToRedeem using the new TVL. After the cooldown the attacker claims ETH worth ~1% more than deposited — the gain is paid by untouched ezETH holders."
    WIKI_RECOMMENDATION = "Re-quote the payout at claim time: recompute `amountToRedeem` using the current TVL/oracle and pay the lesser of (requested, current). Charge a proportional redemption fee, or require a symmetric deposit cooldown, to prevent sandwiching oracle updates. Never pay cached oracle outputs hours/days late"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, 'contract.name_matches: (?i)(withdraw.*queue|withdrawal.*queue|redemption.*queue|cooldown.*vault)']
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(requestWithdraw|withdraw|requestRedeem|createWithdrawRequest|queueWithdrawal)$'}, {'function.body_contains_regex': '(?i)(lookupTokenAmountFromValue|convertToAssets|previewRedeem|calculateTVL|_getPrice|getRate)\\s*\\('}, {'function.writes_storage_matching': '(?i)(amountToRedeem|assetsOut|pendingAssets|cashoutAmount|claimAmount|assetsToReceive)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, "!function.body_contains_regex: '(?i)(min\\s*\\(.*amountToRedeem|Math\\.min.*amountToRedeem|reQuote|reprice.*claim)'", {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — withdraw-queue-amount-frozen-at-request-time: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
