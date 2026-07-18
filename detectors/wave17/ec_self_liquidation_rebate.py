"""
ec-self-liquidation-rebate — generated from reference/patterns.dsl/ec-self-liquidation-rebate.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ec-self-liquidation-rebate.yaml
Source: economic-mining-R61
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EcSelfLiquidationRebate(AbstractDetector):
    ARGUMENT = "ec-self-liquidation-rebate"
    HELP = "Liquidation function allows msg.sender == borrower; attacker self-liquidates to pocket liquidation bonus from protocol reserves."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ec-self-liquidation-rebate.yaml"
    WIKI_TITLE = "Self-liquidation rebate — no liquidator != borrower check"
    WIKI_DESCRIPTION = "The liquidation function does not enforce that the liquidator (msg.sender or explicit liquidator param) is different from the borrower. This allows a position holder to open an undercollateralized position and immediately liquidate themselves, capturing the liquidation bonus (typically 5-15%) at the expense of the protocol's insurance fund or other depositors."
    WIKI_EXPLOIT_SCENARIO = "Protocol offers 10% liquidation bonus. Attacker deposits $1000 collateral, borrows $900 (90% LTV = max). Manipulates price to make position undercollateralized. Calls liquidate(attacker, attacker) as both borrower and liquidator. Receives $990 of collateral for repaying $900 debt. Profit: $90 liquidation bonus from protocol."
    WIKI_RECOMMENDATION = "Add `require(msg.sender != borrower, 'no self-liquidation')` as an early check in the liquidation function. Some protocols allow self-liquidation for de-risking but disable the bonus in that case: if `msg.sender == borrower` set liquidationBonus = 0."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'liquidat|seize|repayBorrowBehalf|forceLiquidate'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'liquidat|seize|repayBorrowBehalf|flashLiquidate'}, {'function.has_param_name_matching': 'borrower|account|debtor|underwater'}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.body_contains_regex': 'msg\\.sender|liquidator'}, {'function.body_contains_regex': 'bonus|reward|incentive|discount|liquidationBonus|seize'}, {'function.body_not_contains_regex': 'msg\\.sender\\s*!=\\s*\\w+|require\\s*\\(\\s*liquidator\\s*!=|borrower\\s*!=\\s*msg\\.sender|self.*liquidat'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — ec-self-liquidation-rebate: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
