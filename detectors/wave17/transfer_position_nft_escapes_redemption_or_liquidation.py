"""
transfer-position-nft-escapes-redemption-or-liquidation — generated from reference/patterns.dsl/transfer-position-nft-escapes-redemption-or-liquidation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py transfer-position-nft-escapes-redemption-or-liquidation.yaml
Source: auditooor-R75-c4-lending-dittoeth-289
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class TransferPositionNftEscapesRedemptionOrLiquidation(AbstractDetector):
    ARGUMENT = "transfer-position-nft-escapes-redemption-or-liquidation"
    HELP = "Position NFT / CDP transfer re-keys storage (deletes old record, creates new) without asserting the position is healthy. Borrower front-runs liquidation/redemption tx; the liquidator's tx reverts because the (oldOwner, id) record is gone."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/transfer-position-nft-escapes-redemption-or-liquidation.yaml"
    WIKI_TITLE = "Position transfer provides liquidation / redemption evasion"
    WIKI_DESCRIPTION = "When a position (short record, CDP NFT, loan position) is keyed as `mapping[asset][owner][id]` and transfer-NFT logic deletes the old entry and recreates it under the new owner, any pending operation that encoded (owner, id) as its target becomes stale in one block. Liquidators and redeemers submit transactions citing the old owner; the borrower observes the mempool and front-runs by transferring "
    WIKI_EXPLOIT_SCENARIO = "Alice's short has CR = 140% (primary liquidation threshold 150%). Bob submits liquidate(asset, Alice, id=3). Alice sees the tx, front-runs with `NFT.transferFrom(Alice, Alice2, tokenId)`. Inside transfer: old record at [asset][Alice][3] is deleted (status=Closed), new record at [asset][Alice2][newId] is created with same debt/collateral. Bob's liquidate() reverts — status is Closed. Alice can repe"
    WIKI_RECOMMENDATION = "Before re-keying, require position.isHealthy() (collateral ratio above liquidation threshold) and position.isNotInRedemptionProposal(). Alternatively, make transfer a no-op on the accounting keys (keep the record keyed by tokenId only, not by owner) so pending liquidation tx cannot be desynced."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(shortRecord|position|loan|collateral).*(owner|shorter|borrower)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(transfer(From)?|safeTransfer(From)?|_?transferPosition|_?transferShortRecord|_?transferLoan)'}, {'function.body_contains_regex': '(?i)(delete\\s+\\w+\\[\\s*(asset\\s*,\\s*)?from\\s*\\]|status\\s*=\\s*SR\\.Closed|status\\s*=\\s*LoanStatus\\.(Closed|Transferred)|_delete(Short|Loan|Position))'}, {'function.body_not_contains_regex': '(?i)(getCR|collateralRatio|healthFactor|isLiquidatable|checkHealth|LibShortRecord\\.isLiquidatable|isRedeemable)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — transfer-position-nft-escapes-redemption-or-liquidation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
