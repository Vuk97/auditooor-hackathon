"""
borrow-can-drain-protocol-reserves — generated from reference/patterns.dsl/borrow-can-drain-protocol-reserves.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py borrow-can-drain-protocol-reserves.yaml
Source: auditooor-R75-c4-lending-revert-lend-327
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BorrowCanDrainProtocolReserves(AbstractDetector):
    ARGUMENT = "borrow-can-drain-protocol-reserves"
    HELP = "Borrow-cap check compares debt vs totalLent but doesn't reserve the protocol's safety cushion (reserves). Fully-collateralized borrow can strip the reserve."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/borrow-can-drain-protocol-reserves.yaml"
    WIKI_TITLE = "Borrow cap ignores protocol reserves, enabling drain of safety cushion"
    WIKI_DESCRIPTION = "A lending vault tracks three numbers: total assets in the pool, total lent out, and protocol reserves (the excess of `balance + debt - lent` set aside for covering bad-debt liquidations and as a team withdrawable fee). The borrow path bounds new debt with `debtSharesTotal <= totalLent`, but does not subtract reserves. A well-collateralized borrower can legitimately drain the entire pool including "
    WIKI_EXPLOIT_SCENARIO = "Vault has 100 USDC balance, 70 lent, 80 deposited, so reserves = 100 + 70 - 80 = 90? Actually reserves = min... simplifying: reserves = 10 protocol cushion, 90 ready to borrow. Bug lets Alice borrow 100 (up to totalLent), including the 10 reserve. Alice's position later goes underwater by 5; protocol has no cushion. The 5 comes straight off depositors' shares."
    WIKI_RECOMMENDATION = "Compute `available = balance - reserves` (or equivalently pull `available` out of `_getAvailableBalance`) and cap new borrow by available, not by balance/lent. Alternatively, reduce `totalLent` by reserves in the cap check: `debtSharesTotal + shares <= _convertToShares(totalLent - reserves)`."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(_getAvailableBalance|withdrawReserves|reserveFactor|reserveShares)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^borrow$|^_borrow$|^borrowInternal$'}, {'function.body_contains_regex': '(?i)debtSharesTotal\\s*>\\s*_convertToShares\\s*\\(\\s*\\w*Lent|debtSharesTotal\\s*>\\s*totalLent'}, {'function.body_not_contains_regex': '(?i)(available\\s*-\\s*reserves|balance\\s*-\\s*reserves|getAvailableBalance.*available|_getAvailableBalance\\s*\\([^)]*\\).*\\.available)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — borrow-can-drain-protocol-reserves: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
