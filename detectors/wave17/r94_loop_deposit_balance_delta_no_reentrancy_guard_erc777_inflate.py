"""
r94-loop-deposit-balance-delta-no-reentrancy-guard-erc777-inflate — generated from reference/patterns.dsl/r94-loop-deposit-balance-delta-no-reentrancy-guard-erc777-inflate.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-deposit-balance-delta-no-reentrancy-guard-erc777-inflate.yaml
Source: solodit-2497-c4-rubicon-bathtoken
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopDepositBalanceDeltaNoReentrancyGuardErc777Inflate(AbstractDetector):
    ARGUMENT = "r94-loop-deposit-balance-delta-no-reentrancy-guard-erc777-inflate"
    HELP = "r94-loop-deposit-balance-delta-no-reentrancy-guard-erc777-inflate"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-deposit-balance-delta-no-reentrancy-guard-erc777-inflate.yaml"
    WIKI_TITLE = "r94-loop-deposit-balance-delta-no-reentrancy-guard-erc777-inflate"
    WIKI_DESCRIPTION = "r94-loop-deposit-balance-delta-no-reentrancy-guard-erc777-inflate"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-deposit-balance-delta-no-reentrancy-guard-erc777-inflate"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(BathToken|Vault|Deposit|ERC4626|Supply|Pool)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(^_deposit$|^deposit$|mintShares|joinVault|supply|stake|addLiquidity|provideLiquidity)'}, {'function.source_matches_regex': '(balanceBefore[\\s\\S]{0,400}?balanceAfter[\\s\\S]{0,400}?(_mint|mintShares|shares\\s*\\+=)|preBalance[\\s\\S]{0,400}?postBalance[\\s\\S]{0,400}?(_mint|mintShares))'}, {'function.not_source_matches_regex': '(nonReentrant|reentrancyGuard|_status\\s*=\\s*ENTERED|mutex|lockAcquire|depositLock)'}]

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
                info = [f, f" — r94-loop-deposit-balance-delta-no-reentrancy-guard-erc777-inflate: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
