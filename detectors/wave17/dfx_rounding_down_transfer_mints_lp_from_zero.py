"""
dfx-rounding-down-transfer-mints-lp-from-zero — generated from reference/patterns.dsl/dfx-rounding-down-transfer-mints-lp-from-zero.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py dfx-rounding-down-transfer-mints-lp-from-zero.yaml
Source: auditooor-R76-immunefi-dfx-$100k
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DfxRoundingDownTransferMintsLpFromZero(AbstractDetector):
    ARGUMENT = "dfx-rounding-down-transfer-mints-lp-from-zero"
    HELP = "Deposit path computes `transferAmount = user_input * rate / 1eN`, then transfers it and mints shares — but does not require `transferAmount > 0`. Low-decimal tokens round to zero; attacker loops to accumulate free LP."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/dfx-rounding-down-transfer-mints-lp-from-zero.yaml"
    WIKI_TITLE = "Rounded-down transfer amount still mints non-zero LP shares"
    WIKI_DESCRIPTION = "A deposit/mint path derives the actual token transfer amount by an integer division (`x * rate / 10^N`). For low-decimal tokens (EURS=2, GUSD=2, some wrapped assets=6) and certain rate values the division rounds down to zero — yet the LP-mint calculation uses a separate (non-zero) rounded value. The function transfers 0 tokens but credits the user with non-zero shares. A single transaction can loo"
    WIKI_EXPLOIT_SCENARIO = "DFX AssimilatorV2.intakeNumeraireLPRatio computed transferAmount but didn't require it > 0. For 1 EURS deposit the amount rounded to zero yet 190 USDC of LP were minted per cycle. ~10k loops in one tx → ~$190 profit per pass of the $237k pool. $100k bounty."
    WIKI_RECOMMENDATION = "Every deposit/mint/redeem path that performs integer division MUST `require(transferAmount > 0)` AND `require(sharesMinted > 0)`. Additionally assert that `sharesMinted * totalAssets <= transferAmount * totalSupply` (no dilution). Property test: `forall (amount, rate): either revert OR (transferAmou"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(Assimilator|Curve|StableSwap|Pool|Vault|LiquidityPool|Pair|Router|LP|Numeraire|MetaPool|Pegged|ERC4626|AMM)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(deposit|mint|addLiquidity|intakeNumeraire|intakeNumeraireLPRatio|intakeRaw|viewDeposit|_mintShares|_deposit|previewDeposit)\\w*$'}, {'function.body_contains_regex': '(?i)\\*\\s*(?:rate|numeraire|pegged)\\s*/|mulDiv\\s*\\([^)]*,\\s*\\d+\\s*\\)|/\\s*(?:1e18|10\\*\\*18|RATE_PRECISION)'}, {'function.body_not_contains_regex': '(?i)require\\s*\\(\\s*(?:amount|transferAmount|amt)\\s*>\\s*0\\s*\\)|amount\\s*==\\s*0\\s*\\|\\|\\s*revert|assert\\s*\\(\\s*amount\\s*>'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.body_contains_regex': '(?i)safeTransferFrom\\s*\\([^)]*amount|transferFrom\\s*\\([^)]*amount|_mint\\s*\\([^)]*shares'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(super\\._deposit|super\\._mint|ERC4626\\.|view\\s+returns|pure\\s+returns|_assertNonZero|previewMint|previewDeposit\\s*\\(|require\\s*\\(\\s*shares\\s*>\\s*0)'}]

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
                info = [f, f" — dfx-rounding-down-transfer-mints-lp-from-zero: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
