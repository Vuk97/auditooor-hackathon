"""
receipt-decimals-read-after-burn — generated from reference/patterns.dsl/receipt-decimals-read-after-burn.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py receipt-decimals-read-after-burn.yaml
Source: solodit/sherlock/debita-H1-44224
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ReceiptDecimalsReadAfterBurn(AbstractDetector):
    ARGUMENT = "receipt-decimals-read-after-burn"
    HELP = "View helper aggregates both live state (ownerOf) and immutable metadata (decimals) into one struct and reverts when the NFT is burned. Downstream claim / payout paths that only need metadata are permanently DoS'd once the NFT is withdrawn."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/receipt-decimals-read-after-burn.yaml"
    WIKI_TITLE = "Data helper aggregates burn-sensitive ownerOf with metadata — claim paths DoS after burn"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. A view helper gathers various fields about an NFT receipt into a single struct — token id, underlying address, decimals, vault, and current owner via `ownerOf`. ERC-721's `ownerOf` reverts (`ERC721NonexistentToken`) when the token has been burned. Downstream functions may only need `.decimals`, but the whole helper reverts as soon as `ownerO"
    WIKI_EXPLOIT_SCENARIO = "Borrower posts veNFT as collateral, defaults. Auction runs, buyer wins and receives the receipt NFT. Buyer burns the receipt via `veNFTVault.withdraw()` to extract the real veNFT. Lenders now try `DebitaV3Loan.claimCollateralAsLender(0)` — internally calls `getDataByReceipt(receiptID)`, which reverts on `ownerOf(receiptID)`. Lender proceeds (the auction payment tokens) are locked in the loan contr"
    WIKI_RECOMMENDATION = "Inline the metadata reads (decimals, underlying) in the claim path, avoiding the full struct helper. If the helper must be used, make `ownerOf` optional: use `_ownerOf(id)` and set `OwnerIsManager = false` on burned receipts, or wrap the call in `try/catch` and fall back to address(0). Always separa"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(receipt|ownerOf|decimals|underlying|vault)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.state_mutability': 'view'}, {'function.body_contains_regex': 'receiptInstance\\s*\\(|struct\\s+\\w+\\s*\\{|\\w+\\s+memory\\s+\\w+\\s*=\\s*\\w+\\s*\\(\\s*\\{'}, {'function.body_contains_regex': '\\.ownerOf\\s*\\(|\\bownerOf\\s*\\('}, {'function.name_matches': '(get\\w*Data|get\\w*Info|read\\w*|fetch\\w*)'}, {'function.body_not_contains_regex': 'try\\s+\\w+\\.ownerOf|_ownerOf\\s*\\(|_exists\\s*\\(|isBurned'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': False}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — receipt-decimals-read-after-burn: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
