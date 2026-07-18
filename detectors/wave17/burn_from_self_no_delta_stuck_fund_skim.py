"""
burn-from-self-no-delta-stuck-fund-skim — generated from reference/patterns.dsl/burn-from-self-no-delta-stuck-fund-skim.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py burn-from-self-no-delta-stuck-fund-skim.yaml
Source: auditooor-R77-polymarket-CollateralToken-unwrap
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BurnFromSelfNoDeltaStuckFundSkim(AbstractDetector):
    ARGUMENT = "burn-from-self-no-delta-stuck-fund-skim"
    HELP = "Function burns from `address(this)` assuming the caller pre-transferred the exact `_amount`. No delta check means donated / stuck tokens at address(this) can be burned to release backing assets (vault drainage)."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/burn-from-self-no-delta-stuck-fund-skim.yaml"
    WIKI_TITLE = "Burn-from-self without delta check enables vault drainage via stuck-fund skim"
    WIKI_DESCRIPTION = "Wrapped-token contracts frequently delegate their unwrap to a WRAPPER_ROLE-gated function that burns from `address(this)` (expecting the caller to have pre-transferred the user's wrapped tokens). If the contract accumulates stuck wrapped tokens (from donation mistakes, refunds, dust), a malicious or buggy WRAPPER_ROLE caller can invoke `unwrap(_amount)` WITHOUT pre-transferring — the burn succeeds"
    WIKI_EXPLOIT_SCENARIO = "A WRAPPER_ROLE contract A has an unintended code path that calls `collateralToken.unwrap(USDC, attacker, 100)` without first transferring 100 pUSD from anyone. The CollateralToken contract has 100 stuck pUSD from an earlier user typo. `_asset.safeTransferFrom(VAULT, attacker, 100)` moves 100 USDC out. `_burn(address(this), 100)` succeeds. Vault is now 100 USDC short against the outstanding pUSD su"
    WIKI_RECOMMENDATION = "Delta-check the contract's self-balance before and after the expected deposit:\n```\nuint256 before = balanceOf(address(this));\n// caller must transfer _amount in between — check with require\nuint256 after_ = balanceOf(address(this));\nrequire(after_ >= before + _amount, \"pUSD not deposited\");\n"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)_burn\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)|WRAPPER_ROLE|unwrap'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)unwrap|redeem|convertFrom'}, {'function.body_contains_regex': '(?i)_burn\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)'}, {'function.body_not_contains_regex': '(?i)balanceBefore|bal[_]?before|require\\s*\\(\\s*balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\)\\s*>=\\s*\\w*[Bb]alanceBefore\\s*\\+\\s*\\w*[Aa]mount'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — burn-from-self-no-delta-stuck-fund-skim: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
