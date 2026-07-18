"""
erc4626-preview-redeem-rounding-up — generated from reference/patterns.dsl/erc4626-preview-redeem-rounding-up.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py erc4626-preview-redeem-rounding-up.yaml
Source: solodit-novel/slice_aa-glif
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Erc4626PreviewRedeemRoundingUp(AbstractDetector):
    ARGUMENT = "erc4626-preview-redeem-rounding-up"
    HELP = "ERC-4626 spec requires `previewRedeem` to round DOWN (disadvantage user). Using `Rounding.Up` inflates previewed amounts, producing integrations that over-commit."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/erc4626-preview-redeem-rounding-up.yaml"
    WIKI_TITLE = "previewRedeem uses Rounding.Up (spec violation)"
    WIKI_DESCRIPTION = "EIP-4626 mandates `previewRedeem` returns shares→assets rounded DOWN, and `previewMint` returns assets→shares rounded UP. Reversing either direction yields on-chain executions that differ from preview, breaking downstream contracts that rely on preview for sizing."
    WIKI_EXPLOIT_SCENARIO = "A router uses `previewRedeem(shares)` to size a subsequent swap leg. Actual `redeem` rounds down; router over-swaps, leaving residual dust dust the router cannot reclaim."
    WIKI_RECOMMENDATION = "Use `Math.Rounding.Down` in `previewRedeem` / `previewWithdraw`. Match OpenZeppelin's ERC4626 reference."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'previewRedeem|previewWithdraw'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(previewRedeem|previewWithdraw)$'}, {'function.body_contains_regex': 'Rounding\\.Up|mulDivUp|ceil|roundUp|_mulDiv\\s*\\([^)]*,\\s*true\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — erc4626-preview-redeem-rounding-up: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
