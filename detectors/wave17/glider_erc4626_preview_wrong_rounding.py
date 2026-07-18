"""
glider-erc4626-preview-wrong-rounding — generated from reference/patterns.dsl/glider-erc4626-preview-wrong-rounding.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-erc4626-preview-wrong-rounding.yaml
Source: hexens-glider/incorrect-rounding-direction-in-erc4626-preview-fu
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderErc4626PreviewWrongRounding(AbstractDetector):
    ARGUMENT = "glider-erc4626-preview-wrong-rounding"
    HELP = "`previewDeposit` / `previewRedeem` rounds UP (Ceil). Per EIP-4626 they MUST round DOWN so that shares received / assets returned are not over-stated — otherwise the reverse `previewMint`/`previewWithdraw` disagree with deposit/redeem and attackers can mint more shares than backed or redeem more asse"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-erc4626-preview-wrong-rounding.yaml"
    WIKI_TITLE = "ERC-4626 previewDeposit / previewRedeem rounds up (should floor)"
    WIKI_DESCRIPTION = "EIP-4626 rounding spec: `previewDeposit` (assets→shares, shares out) → floor; `previewMint` (shares→assets, assets in) → ceil; `previewWithdraw` (assets→shares, shares in) → ceil; `previewRedeem` (shares→assets, assets out) → floor. Swapping the direction on deposit/redeem lets a user take out more than their fair share via the preview-quote contract."
    WIKI_EXPLOIT_SCENARIO = "`previewRedeem(shares)` uses `mulDivUp` → reports 1 wei more than the floored value. Aggregator consults preview, sends shares with that expected output, downstream redeem gives the same rounded-up amount (or reverts in the vault, again breaking batched UX). Repeated arbitrage across the 1-wei drift drains the vault."
    WIKI_RECOMMENDATION = "`previewDeposit` / `previewRedeem` → `mulDivDown` (Floor). `previewMint` / `previewWithdraw` → `mulDivUp` (Ceil). Reference OZ 4.9 ERC4626 implementation."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'previewDeposit|previewMint|previewWithdraw|previewRedeem'}]
    _MATCH = [{'function.name_matches': '^(previewDeposit|previewRedeem)$'}, {'function.kind': 'external_or_public'}, {'function.body_contains_regex': 'Ceil|mulDivUp|RoundingUp|Math\\.Rounding\\.Up|Math\\.Rounding\\.Ceil|roundUp'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-erc4626-preview-wrong-rounding: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
