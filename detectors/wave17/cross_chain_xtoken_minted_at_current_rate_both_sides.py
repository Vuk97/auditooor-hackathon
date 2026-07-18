"""
cross-chain-xtoken-minted-at-current-rate-both-sides — generated from reference/patterns.dsl/cross-chain-xtoken-minted-at-current-rate-both-sides.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py cross-chain-xtoken-minted-at-current-rate-both-sides.yaml
Source: auditooor-R75-c4-yield-2024-04-renzo-145
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CrossChainXtokenMintedAtCurrentRateBothSides(AbstractDetector):
    ARGUMENT = "cross-chain-xtoken-minted-at-current-rate-both-sides"
    HELP = "L1 bridge receiver mints at current L1 rate while L2 already minted xToken at L2 rate, creating permanent divergence in lockbox 1:1 backing."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/cross-chain-xtoken-minted-at-current-rate-both-sides.yaml"
    WIKI_TITLE = "Cross-chain yield bridge mints xToken and underlying at independent current rates, breaking 1:1 lockbox peg"
    WIKI_DESCRIPTION = "Two-leg yield bridges (deposit on L2 → mint xToken; sweep to L1 → mint wrapped share and lock in XERC20Lockbox) often mint both legs using the spot rate at that leg's moment. Between the L2 mint and the L1 completion (minutes–days, depending on the bridge), the yield-bearing asset's rate changes due to rewards or slashing. When the L1 side mints fewer shares than the L2 side minted xTokens, some x"
    WIKI_EXPLOIT_SCENARIO = "User deposits 1 ETH on L2 at rate 1.0 → receives 1 xezETH. ezETH rate rises to 2.0 during the bridge delay. On L1, 1 ETH is deposited into RestakeManager which mints only 0.5 ezETH. Lockbox now holds 0.5 ezETH but owes 1 xezETH. User can redeem only 0.5 xezETH; the other 0.5 is worthless."
    WIKI_RECOMMENDATION = "Pass the L2-minted xToken amount as bridge payload and mint exactly that number of shares on L1 regardless of spot rate, using surplus deposit value as a protocol fee / buffer. Alternatively, defer the L2 xToken mint until the L1 confirmation arrives with the actual share count."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, 'contract.name_matches: (?i)(xRenzoBridge|xDeposit|xReceive|lockbox|XERC20)']
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(xReceive|onReceive|receiveFromBridge|handleBridge)'}, {'function.body_contains_regex': '(?i)(depositETH|depositAsset|deposit\\s*\\()'}, {'function.body_contains_regex': '(?i)(lockbox|XERC20Lockbox)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, "!function.body_contains_regex: '(?i)(sharesMintedOnL2|expectedShares|minted.*param|_amountMinted\\s*=\\s*abi\\.decode)'", {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — cross-chain-xtoken-minted-at-current-rate-both-sides: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
