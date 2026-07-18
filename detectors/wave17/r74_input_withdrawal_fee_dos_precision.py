"""
r74-input-withdrawal-fee-dos-precision — generated from reference/patterns.dsl/r74-input-withdrawal-fee-dos-precision.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r74-input-withdrawal-fee-dos-precision.yaml
Source: r74b-cross-firm-tob+cs
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R74InputWithdrawalFeeDosPrecision(AbstractDetector):
    ARGUMENT = "r74-input-withdrawal-fee-dos-precision"
    HELP = "Withdraw fee computed by mulDiv floor; on small amounts fee rounds to zero but protocol accounting still charges fee elsewhere, eventually underflowing and DoS-ing withdrawals."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r74-input-withdrawal-fee-dos-precision.yaml"
    WIKI_TITLE = "Withdrawal fee rounded down breaks invariant and DoS-es later withdrawals"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. fee = amount * feeRate / BASIS uses integer floor division. For small withdrawal amounts (dust, last-user cleanup), the fee rounds to 0. If the vault's total-assets accounting was charged a fee-estimate at time of deposit (e.g., computed over the whole vault rather than per-withdrawal), the cumulative on-chain fee drifts above what per-withd"
    WIKI_EXPLOIT_SCENARIO = "An attacker detects that the vault charges a protocol-level fee on rebalance but a user-level fee (mulDiv floor) on withdrawal. The attacker withdraws 1 wei ten million times: each user-level fee floors to 0, each protocol-level fee rebalance charges 1 atomic unit. After N = rebalance_frequency * user_count many withdrawals, the vault's bookkept totalAssets is below its actual balance by a few wei"
    WIKI_RECOMMENDATION = "Use mulDivUp (round fee up) so fee + net >= amount always holds, and either refund the rounding residual to the pool or the user explicitly. Alternatively, unify protocol-fee and per-withdrawal-fee into a single mulDiv computed at the same rounding direction. Add invariant test: sum(withdrawn_fees) "

    _PRECONDITIONS = [{'contract.source_matches_regex': '(withdraw|redeem|burn|unwind)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(withdraw|redeem|burn|unwind|exit)'}, {'function.body_contains_regex': 'fee\\s*=\\s*[^;]*[\\*/]\\s*[^;]*(1e18|1e4|BASIS|BPS|WAD|RAY|denom|DENOMINATOR|10000|1000000)'}, {'function.body_not_contains_regex': 'mulDivUp|mulDivRoundingUp|ceilDiv|roundUp|Math\\.mulDiv\\s*\\([^)]*,\\s*\\w+\\s*,\\s*\\w+\\s*,\\s*Math\\.Rounding\\.Up|\\+\\s*1\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r74-input-withdrawal-fee-dos-precision: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
