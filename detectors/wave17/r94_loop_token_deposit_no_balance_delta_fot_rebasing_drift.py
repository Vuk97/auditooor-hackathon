"""
r94-loop-token-deposit-no-balance-delta-fot-rebasing-drift — generated from reference/patterns.dsl/r94-loop-token-deposit-no-balance-delta-fot-rebasing-drift.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-token-deposit-no-balance-delta-fot-rebasing-drift.yaml
Source: solodit-34506-codehawks-beedle-lender
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopTokenDepositNoBalanceDeltaFotRebasingDrift(AbstractDetector):
    ARGUMENT = "r94-loop-token-deposit-no-balance-delta-fot-rebasing-drift"
    HELP = "r94-loop-token-deposit-no-balance-delta-fot-rebasing-drift"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-token-deposit-no-balance-delta-fot-rebasing-drift.yaml"
    WIKI_TITLE = "r94-loop-token-deposit-no-balance-delta-fot-rebasing-drift"
    WIKI_DESCRIPTION = "r94-loop-token-deposit-no-balance-delta-fot-rebasing-drift"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-token-deposit-no-balance-delta-fot-rebasing-drift"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(Lender|Vault|Pool|Supply|Deposit|Stake)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(deposit|supply|stake|provideLiquidity|addCollateral|fund|topUp|mintSharesFor)'}, {'function.source_matches_regex': '(transferFrom\\s*\\([\\s\\S]{0,300}?\\)\\s*;\\s*[\\s\\S]{0,300}?(balances|totalDeposits|shares)[\\s\\S]{0,60}?\\+=\\s*\\w*amount|safeTransferFrom\\s*\\([\\s\\S]{0,300}?\\)\\s*;\\s*[\\s\\S]{0,300}?_mint\\s*\\(\\s*\\w+\\s*,\\s*\\w*amount\\s*\\))'}, {'function.not_source_matches_regex': '(balanceBefore\\s*=\\s*\\w*balanceOf|preBalance\\s*=\\s*\\w*balanceOf|balanceAfter\\s*-\\s*balanceBefore|actualReceived\\s*=|received\\s*=\\s*\\w*balanceAfter)'}]

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
                info = [f, f" — r94-loop-token-deposit-no-balance-delta-fot-rebasing-drift: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
