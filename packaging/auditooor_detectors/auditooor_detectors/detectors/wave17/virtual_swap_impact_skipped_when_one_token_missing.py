"""
virtual-swap-impact-skipped-when-one-token-missing — generated from reference/patterns.dsl/virtual-swap-impact-skipped-when-one-token-missing.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py virtual-swap-impact-skipped-when-one-token-missing.yaml
Source: lisa-mine-r99-case-01824-sherlock-gmx-2023-04
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class VirtualSwapImpactSkippedWhenOneTokenMissing(AbstractDetector):
    ARGUMENT = "virtual-swap-impact-skipped-when-one-token-missing"
    HELP = "Swap-price-impact helper short-circuits to zero impact (or returns an empty struct) as soon as it detects that ONE side of the trade lacks virtual inventory. Markets where token A has a virtual inventory but token B does not bypass the virtual-swap impact entirely — traders preferentially route thro"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/virtual-swap-impact-skipped-when-one-token-missing.yaml"
    WIKI_TITLE = "Virtual price-impact helper skips ALL impact when one collateral token lacks virtual inventory"
    WIKI_DESCRIPTION = "Pattern fires on `getPriceImpactUsd`-style helpers that early-return zero / an empty struct when `virtualPoolAmountForTokenB == 0` (or `hasVirtualInventoryTokenB == false`) — even when token A still has a configured virtual inventory. The asymmetric guard treats the absence on either side as a license to bypass the virtual-impact cap entirely; traders find these mixed markets and route through the"
    WIKI_EXPLOIT_SCENARIO = "GMX configures BTC and ETH with virtual inventories but onboards a new long-tail market USDC/STG without setting virtualPoolAmountForTokenB. A trader who would otherwise pay 50bps virtual impact for an asymmetric BTC trade routes via USDC (no impact), STG (no impact, no virtual), gets out into BTC at the second hop, paying zero virtual cost. The cap exists in code but is unreachable for any path t"
    WIKI_RECOMMENDATION = "If either token has a virtual inventory configured, compute the virtual impact using the existing token's inventory and the live-pool inventory of the other side (treat the missing side as the live spot pool). Equivalently, route mixed-market swaps through a wrapper that decomposes the trade into tw"

    _PRECONDITIONS = [{'contract.has_function_matching': 'getPriceImpact|priceImpact|getVirtualInventory|virtualPriceImpact|getSwap.*Impact'}, {'contract.source_matches_regex': 'virtualInventory|virtualPoolAmount|virtualToken|virtualPriceImpact'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': 'getPriceImpact|getVirtualPriceImpact|priceImpact|swapPriceImpactUsd|getVirtualInventoryForSwaps|getVirtualImpact'}, {'function.body_contains_regex': '\\b(virtualPoolAmount[A-Za-z]*|virtualInventory[A-Za-z]*)\\s*(==|<=)\\s*0|hasVirtualInventoryToken[AB]\\s*==\\s*false|!\\s*hasVirtual'}, {'function.body_contains_regex': '\\breturn\\s+(0\\s*;|nilImpact|emptyImpact|new\\s+|[A-Z][A-Za-z]*Result\\s*\\(|[A-Z][A-Za-z]*\\s*\\(\\{[^}]*[Pp]riceImpact[^}]*:\\s*0)'}, {'function.body_not_contains_regex': 'fallbackPool|nominalImpact|nonVirtualImpact|computeSpotImpact|callMarketLevelImpact|even.*one.*token.*has.*virtual'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" — virtual-swap-impact-skipped-when-one-token-missing: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
