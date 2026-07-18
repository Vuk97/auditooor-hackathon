"""
transfer-nft-bid-amount-vs-listed-price-unchecked — generated from reference/patterns.dsl/transfer-nft-bid-amount-vs-listed-price-unchecked.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py transfer-nft-bid-amount-vs-listed-price-unchecked.yaml
Source: auditooor-R75-code4rena-2024-10-coded-estate-12
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class TransferNftBidAmountVsListedPriceUnchecked(AbstractDetector):
    ARGUMENT = "transfer-nft-bid-amount-vs-listed-price-unchecked"
    HELP = "transfer_nft transfers ownership unconditionally and defaults amount to 0 when recipient has no bid — missing equality check against the listed price enables zero-payment theft."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/transfer-nft-bid-amount-vs-listed-price-unchecked.yaml"
    WIKI_TITLE = "transfer_nft lets anyone steal an approved NFT by defaulting missing bid to zero amount"
    WIKI_DESCRIPTION = "`transfer_nft(recipient)` loops over `token.bids` to find one with `address == recipient`. If none is found, the default `amount = 0` is used and the function still runs: it clears approvals, assigns `token.owner = recipient`, and performs the `BankMsg::Send` only when amount > 0 (sending nothing in that branch). The NFT is transferred free. Combined with a stale approval (bidder cancelled previou"
    WIKI_EXPLOIT_SCENARIO = "Seller lists at 1000 USDC, auto_approve. Attacker places bid and cancels (retaining approval). Attacker calls `transfer_nft(attacker, token_id)`. Loop finds no bid for attacker → amount = 0 → ownership transfers to attacker, seller receives zero."
    WIKI_RECOMMENDATION = "At the top of transfer_nft, require `bid.address == recipient && bid.amount >= sell.price`. Revoke approval inside cancel paths. Fail closed if no matching bid is present."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)transfer_nft|transferNft|completeSale|executeTrade'}, {'function.body_contains_regex': '(?i)let\\s+mut\\s+amount\\s*=\\s*Uint128::from\\s*\\(\\s*0|uint256\\s+amount\\s*=\\s*0'}, {'function.body_contains_regex': '(?i)token\\.owner\\s*=|_transferOwnership|ownership_transfer'}, {'function.body_not_contains_regex': '(?i)require\\s*\\([^)]*amount\\s*(>=|==)\\s*[\\w\\.]*price|require\\s*\\([^)]*bid\\.amount'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — transfer-nft-bid-amount-vs-listed-price-unchecked: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
