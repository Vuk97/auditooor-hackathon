"""
aave-flashloan-premium-on-debt-bearing-leg — generated from reference/patterns.dsl/aave-flashloan-premium-on-debt-bearing-leg.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py aave-flashloan-premium-on-debt-bearing-leg.yaml
Source: auditooor-R71-fixdiff-mined-aave-v3-core-7b2a2840e1
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AaveFlashloanPremiumOnDebtBearingLeg(AbstractDetector):
    ARGUMENT = "aave-flashloan-premium-on-debt-bearing-leg"
    HELP = "Flashloan routine charges and reports the premium on legs whose interestRateMode != NONE — these legs open a debt position instead of repaying, so charging a premium on them double-charges users and misreports fees in ExecutedWithSuccess."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/aave-flashloan-premium-on-debt-bearing-leg.yaml"
    WIKI_TITLE = "Flashloan premium applied to debt-bearing mode=STABLE/VARIABLE legs"
    WIKI_DESCRIPTION = "Aave v3 executeFlashLoan iterates over (asset, amount, interestRateMode) triples. Legs with interestRateMode==NONE are true flashloans: the borrower must return amount+premium within the callback. Legs with interestRateMode STABLE or VARIABLE are converted into a regular borrow for msg.sender — no repayment happens in the callback, the user simply walks away with a fresh debt position. Pre-fix the"
    WIKI_EXPLOIT_SCENARIO = "A DeFi adapter calls flashLoan with assets=[USDC], modes=[2 (VARIABLE)] expecting to open a borrow. The Aave code computes premium=0.09% and passes it in premiums[] to executeOperation. The adapter records a 'flash fee paid' event into its accounting with the non-zero premium, and deducts it from user collateral — but Aave never actually collected that premium (the repay branch is skipped for mode"
    WIKI_RECOMMENDATION = "Compute the premium per-leg: `totalPremiums[i] = (interestRateModes[i] == InterestRateMode.NONE) ? amount.percentMul(flashloanPremiumTotal) : 0;`. Never report a non-zero premium on a leg that becomes a borrow — the caller's `executeOperation(premiums)` must match the actual on-chain charge."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': 'executeFlashLoan|_flashLoan|flashLoan'}]
    _MATCH = [{'function.kind': 'internal'}, {'function.name_matches': 'executeFlashLoan|_flashLoan'}, {'function.body_contains_regex': 'interestRateMode|InterestRateMode'}, {'function.body_contains_regex': 'percentMul\\(.*(flashloanPremiumTotal|premiumTotal|FLASHLOAN_PREMIUM)'}, {'function.body_not_contains_regex': 'InterestRateMode\\s*\\.\\s*NONE\\s*\\?\\s*.*percentMul|interestRateModes\\[\\s*\\w+\\s*\\]\\s*==\\s*0\\s*\\?\\s*.*percentMul|mode\\s*==\\s*0\\s*\\?\\s*.*\\.percentMul'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — aave-flashloan-premium-on-debt-bearing-leg: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
