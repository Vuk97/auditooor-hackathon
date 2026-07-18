"""
perp-glv-deposit-skips-max-pnl-validation — generated from reference/patterns.dsl/perp-glv-deposit-skips-max-pnl-validation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py perp-glv-deposit-skips-max-pnl-validation.yaml
Source: auditooor-R73-fixdiff-mined-gmx-synthetics-99372453db
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PerpGlvDepositSkipsMaxPnlValidation(AbstractDetector):
    ARGUMENT = "perp-glv-deposit-skips-max-pnl-validation"
    HELP = "validateMaxPnl is inside the market-token branch only. Long/short-token deposit path skips the PnL safety gate and lets users mint GLV at an inflated price when unrealized PnL is extreme."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/perp-glv-deposit-skips-max-pnl-validation.yaml"
    WIKI_TITLE = "validateMaxPnl only runs on market-token deposit branch"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: GLV deposits route either raw long/short tokens or pre-minted market tokens. This row distinguishes the branch-local shape where `validateMaxPnl(...)` appears only inside `if (deposit.isMarketTokenDeposit())` from the clean shape where the PnL gate is hoisted before the branch. NOT_SUBMIT_READY."
    WIKI_EXPLOIT_SCENARIO = "(1) GM/GLV market has enormous unrealized LP PnL — mark-to-market GM price is $2.10, MAX_PNL_FACTOR_FOR_WITHDRAWALS would cap GLV withdrawals (and symmetrically, deposits at above-fair price are capped). (2) Attacker wants to mint GLV at the cheap 'pre-PnL-realized' price. Through the market-token branch, validateMaxPnl reverts. (3) Attacker instead deposits raw long/short tokens (deposit flow). T"
    WIKI_RECOMMENDATION = "Hoist validation checks that are precondition-style (solvency gates, PnL caps, oracle-stale checks) ABOVE any branching on input shape. Anti-pattern: gating a precondition inside one of N branches. Fuzz test: for every executable entry into a GM/GLV minting flow, validateMaxPnl must fire before any "

    _PRECONDITIONS = [{'contract.source_matches_regex': '(validateMaxPnl|MAX_PNL_FACTOR_FOR_DEPOSITS|MAX_PNL_FACTOR_FOR_WITHDRAWALS)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(executeGlvDeposit|_executeGlvDeposit|_transferMarketTokens|executeShift)'}, {'function.body_contains_regex': 'isMarketTokenDeposit\\s*\\(\\s*\\)'}, {'function.body_contains_regex': 'validateMaxPnl'}, {'function.body_contains_regex': 'if\\s*\\(\\s*\\w+\\.isMarketTokenDeposit\\s*\\(\\s*\\)\\s*\\)\\s*\\{[\\s\\S]{0,800}validateMaxPnl'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — perp-glv-deposit-skips-max-pnl-validation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
