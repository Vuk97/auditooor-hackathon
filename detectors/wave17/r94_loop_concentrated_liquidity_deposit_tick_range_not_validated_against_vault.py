"""
r94-loop-concentrated-liquidity-deposit-tick-range-not-validated-against-vault — generated from reference/patterns.dsl/r94-loop-concentrated-liquidity-deposit-tick-range-not-validated-against-vault.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-concentrated-liquidity-deposit-tick-range-not-validated-against-vault.yaml
Source: solodit-65235-pashov-saffron-vaults
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopConcentratedLiquidityDepositTickRangeNotValidatedAgainstVault(AbstractDetector):
    ARGUMENT = "r94-loop-concentrated-liquidity-deposit-tick-range-not-validated-against-vault"
    HELP = "r94-loop-concentrated-liquidity-deposit-tick-range-not-validated-against-vault"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-concentrated-liquidity-deposit-tick-range-not-validated-against-vault.yaml"
    WIKI_TITLE = "r94-loop-concentrated-liquidity-deposit-tick-range-not-validated-against-vault"
    WIKI_DESCRIPTION = "r94-loop-concentrated-liquidity-deposit-tick-range-not-validated-against-vault"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-concentrated-liquidity-deposit-tick-range-not-validated-against-vault"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(Vault|ConcentratedLiquidity|Saffron|RangeVault|UniswapV3Vault)'}]
    _MATCH = [{'function.name_matches': '(?i)^(depositFixed|depositRange|addLiquidityRange|mintPosition|provideRangeLiquidity|depositConcentrated)$'}, {'function.source_matches_regex': '(tickLower[\\s\\S]{0,80}?tickUpper|tick_lower[\\s\\S]{0,80}?tick_upper)'}, {'function.not_source_matches_regex': '(vault\\.tickLower|vaultTickLower|tickLower\\s*>=\\s*\\w*vault\\.tickLower|tickUpper\\s*<=\\s*\\w*vault\\.tickUpper|require\\s*\\(\\s*\\w*tickLower\\s*>=\\s*\\w*vault|alignToVaultTickRange|withinVaultRange)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r94-loop-concentrated-liquidity-deposit-tick-range-not-validated-against-vault: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
