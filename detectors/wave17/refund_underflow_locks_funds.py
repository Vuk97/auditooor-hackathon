"""
refund-underflow-locks-funds — generated from reference/patterns.dsl/refund-underflow-locks-funds.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py refund-underflow-locks-funds.yaml
Source: solodit/C0135
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RefundUnderflowLocksFunds(AbstractDetector):
    ARGUMENT = "refund-underflow-locks-funds"
    HELP = "Refund/redemption path computes `refund = paid - actualCost` via raw subtraction; on Solidity 0.8 an overrun (fee-on-transfer, slippage, rounding) panics and permanently locks the user's funds in the contract."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/refund-underflow-locks-funds.yaml"
    WIKI_TITLE = "Refund underflow in redemption path permanently locks user funds"
    WIKI_DESCRIPTION = "Refund, redeem, withdraw, cancel, and reclaim paths frequently compute the return to the user as `paid - actualCost` or `amountIn - amountConsumed`. If the accounting is imperfect — fee-on-transfer tokens silently skim, AMM slippage pushes actualCost past the quoted cost, or rounding makes consumed > paid — the Solidity-0.8 checked subtraction panics (0x11) and reverts the entire refund call. Beca"
    WIKI_EXPLOIT_SCENARIO = "A user pays `paid = 100` for a swap refund. The router actually consumes `actualCost = 101` due to a fee-on-transfer token skimming one unit in-transit. The refund function computes `return paid - actualCost;`, underflows, panics, and reverts. The user's 100 units are still escrowed but the refund call can never succeed. Variant: `redemption() { userBalance -= redeemAmount; }` with `userBalance < "
    WIKI_RECOMMENDATION = "Wrap every refund subtraction in a saturating floor: `uint256 refund = paid >= actualCost ? paid - actualCost : 0;`. Or validate the invariant before subtracting and early-return with a short-circuit when it fails. Never rely on the Solidity-0.8 revert as a gate inside a refund path — the revert IS "

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(paid|refund|balance|escrow|locked)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '(refund|redeem|withdraw|cancel|reclaim|_refund)'}, {'function.body_contains_regex': {'regex': '(\\w+\\s*-\\s*\\w+\\s*;|\\w+\\s*-=\\s*\\w+)'}}, {'function.body_not_contains_regex': '(unchecked\\s*\\{|SafeMath|saturat|\\bmin\\s*\\(|\\bmax\\s*\\(|\\?\\s*.*:\\s*0)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — refund-underflow-locks-funds: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
