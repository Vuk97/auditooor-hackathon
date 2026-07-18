"""
erc4626-preview-vs-actual-divergence — generated from reference/patterns.dsl/erc4626-preview-vs-actual-divergence.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py erc4626-preview-vs-actual-divergence.yaml
Source: solodit/erc4626-preview-divergence-class
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Erc4626PreviewVsActualDivergence(AbstractDetector):
    ARGUMENT = "erc4626-preview-vs-actual-divergence"
    HELP = "ERC4626 vault's deposit/redeem/mint/withdraw applies fees or extra rounding that the matching preview* function does not model — off-chain callers quoted by preview* receive a different share/asset amount on execution."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/erc4626-preview-vs-actual-divergence.yaml"
    WIKI_TITLE = "ERC4626 preview* diverges from actual deposit/redeem/mint/withdraw"
    WIKI_DESCRIPTION = "EIP-4626 requires preview* to return exactly what the corresponding mutating call would produce under the same on-chain conditions. This contract inherits or implements ERC4626 but the mutating action contains fee-math or ceil-rounding that the preview* path does not mirror. Integrators (aggregators, routers, wallets) price transactions off preview* quotes and will get filled at a worse rate, pote"
    WIKI_EXPLOIT_SCENARIO = "An aggregator asks vault.previewDeposit(1000e6) and receives 998e18 shares. It submits deposit(1000e6, user) with a minShares slippage bound of 997e18. The live deposit path applies a 30 bps entry fee that previewDeposit ignored, so the user actually receives 995e18 shares — the transaction reverts on slippage or, worse, succeeds and silently pays the fee. A griefer can also deliberately front-run"
    WIKI_RECOMMENDATION = "Make deposit/redeem/mint/withdraw call their own preview* helper and use the returned figure as the source of truth, or update preview* to apply identical fee / rounding logic. Unit-test that previewX(input) == actual outcome of X(input) across the full fee and rounding range, including zero-share a"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.inherits_any': ['ERC4626', 'IERC4626', 'ERC4626Upgradeable']}, {'contract.has_function_matching': '(previewDeposit|previewRedeem|previewMint|previewWithdraw)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(deposit|redeem|mint|withdraw)$'}, {'function.body_contains_regex': {'regex': '(\\bfee\\b|feeAmount|_chargeFee|_withdrawFee|_depositFee|ceilDiv|Math\\.ceilDiv|roundUp|mulDivRoundingUp)'}}, {'function.body_not_contains_regex': 'previewDeposit|previewRedeem|previewMint|previewWithdraw'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — erc4626-preview-vs-actual-divergence: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
