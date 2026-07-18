"""
imm-alchemix-liquidate-no-post-solvency-check — generated from reference/patterns.dsl/imm-alchemix-liquidate-no-post-solvency-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py imm-alchemix-liquidate-no-post-solvency-check.yaml
Source: immunefi/alchemix-missing-solvency-check
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ImmAlchemixLiquidateNoPostSolvencyCheck(AbstractDetector):
    ARGUMENT = "imm-alchemix-liquidate-no-post-solvency-check"
    HELP = "liquidate() reduces an account's collateral via an external swap/unwrap but never re-checks collateralization afterwards. Attacker sandwiches the swap with slippage ~0, burns the collateral for dust, and leaves the account with undetected bad debt."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/imm-alchemix-liquidate-no-post-solvency-check.yaml"
    WIKI_TITLE = "Liquidation missing post-swap solvency check (Alchemix AlchemistV2)"
    WIKI_DESCRIPTION = "Self-liquidation entrypoints in CDP/debt systems reduce a user's debt by swapping their yield-bearing collateral back to the underlying asset and crediting the proceeds against the debt balance. When the function accepts a user-supplied `minimumAmountOut = 1` (or trusts a swap adapter with no slippage check) the attacker can front/back-run their own liquidation and burn collateral worth $X for dus"
    WIKI_EXPLOIT_SCENARIO = "Alchemix (Sep 2023): attacker self-liquidates a vault with `minimumAmountOut=1`. The underlying TokenAdapter returns 1 wei of yieldToken for $50k of alETH collateral. `liquidate()` burns $50k of collateral, reduces debt by 1 wei, and returns. The account now has near-zero collateral with full debt outstanding; solvency was never re-verified. Attacker repeats across positions to mint 7k unbacked al"
    WIKI_RECOMMENDATION = "After every debt-reducing or collateral-reducing operation, call `_validate(account)` (or the protocol's equivalent solvency probe) which asserts `collateral * price >= debt * minCollateralizationRatio`. Additionally enforce a protocol-level floor on `minimumAmountOut` as a function of oracle price "

    _PRECONDITIONS = [{'contract.source_matches_regex': '\\bliquidate\\b|\\bunwrap\\b|collateralizationLimit|minimumCollateralization'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(liquidate|_liquidate|liquidateAccount|liquidatePosition)$'}, {'function.body_contains_regex': '_unwrap\\s*\\(|yieldTokenAdapter|IYieldAdapter|unwrap\\s*\\(|swap\\s*\\('}, {'function.body_not_contains_regex': '_validate\\s*\\(|_checkSolvency|_isFullyCollateralized|requireCollateralization|collateralizationCheck|healthFactor|HealthCheck'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — imm-alchemix-liquidate-no-post-solvency-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
