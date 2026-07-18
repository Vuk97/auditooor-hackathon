"""
r94-loop-balancer-pair-oracle-read-only-reentrancy-no-vault-guard-check — generated from reference/patterns.dsl/r94-loop-balancer-pair-oracle-read-only-reentrancy-no-vault-guard-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-balancer-pair-oracle-read-only-reentrancy-no-vault-guard-check.yaml
Source: solodit-18493-sherlock-blueberry-balancer-pair-oracle
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopBalancerPairOracleReadOnlyReentrancyNoVaultGuardCheck(AbstractDetector):
    ARGUMENT = "r94-loop-balancer-pair-oracle-read-only-reentrancy-no-vault-guard-check"
    HELP = "r94-loop-balancer-pair-oracle-read-only-reentrancy-no-vault-guard-check"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-balancer-pair-oracle-read-only-reentrancy-no-vault-guard-check.yaml"
    WIKI_TITLE = "r94-loop-balancer-pair-oracle-read-only-reentrancy-no-vault-guard-check"
    WIKI_DESCRIPTION = "r94-loop-balancer-pair-oracle-read-only-reentrancy-no-vault-guard-check"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-balancer-pair-oracle-read-only-reentrancy-no-vault-guard-check"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(BalancerPairOracle|Oracle|BalancerVault|IVault|LpOracle)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(getPrice|getLpPrice|getPoolPrice|priceOf|latestPrice|computeLpValue|fetchLpPrice)'}, {'function.source_matches_regex': '(getPoolTokens\\s*\\(|vault\\.getPool|IVault\\s*\\(\\s*\\w+\\s*\\)\\s*\\.\\s*getPoolTokens)'}, {'function.not_source_matches_regex': '(manageUserBalance|ensureNotReentered|vaultReentrancyGuard|checkVaultNotEntered|balancerReentrancyCheck)'}]

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
                info = [f, f" — r94-loop-balancer-pair-oracle-read-only-reentrancy-no-vault-guard-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
