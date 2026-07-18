"""
settle-batch-refund-flushes-self-balance — generated from reference/patterns.dsl/settle-batch-refund-flushes-self-balance.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py settle-batch-refund-flushes-self-balance.yaml
Source: cross-engagement-polymarket-Trading-settleTakerOrder-matchOrders
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SettleBatchRefundFlushesSelfBalance(AbstractDetector):
    ARGUMENT = "settle-batch-refund-flushes-self-balance"
    HELP = "Settle / match-orders batch path forwards the contract's full balanceOf(self) (or _getBalance(self)) to the taker as a leftover refund, with no pre-batch snapshot. Any prior-stuck balance — donation, rounding dust, residue from a partial batch, or fee-on-transfer leakage — is flushed to the first su"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/settle-batch-refund-flushes-self-balance.yaml"
    WIKI_TITLE = "Settle / matchOrders refund forwards full self-balance instead of per-batch delta"
    WIKI_DESCRIPTION = "An exchange settlement path (`_settleTakerOrder`, `_matchOrders`, `matchBuyOrders`, `_fillBatch`, etc.) settles a maker/taker batch and, at the end of the batch, refunds the leftover `makerAssetId` (collateral or position token) back to the taker. The implementation reads `_getBalance(makerAssetId)` or `IERC20(token).balanceOf(address(this))` and forwards that entire value to `takerOrder.maker` / "
    WIKI_EXPLOIT_SCENARIO = "v1 `CTFExchange._matchOrders` ends every match with `uint256 refund = _getBalance(makerAssetId); if (refund > 0) _transfer(address(this), takerOrder.maker, makerAssetId, refund);`. A mistransfer of 1,000 USDC sits in the exchange. An operator matches the next BUY taker for an unrelated market. The taker receives their normal collateral output PLUS the entire 1,000 USDC residue. The honest user who"
    WIKI_RECOMMENDATION = "Snapshot the asset's contract balance at the top of the settle/match path and forward only the delta:\n\n```solidity\nuint256 balanceBefore = _getBalance(makerAssetId);\n// ... pull from taker, fill makers ...\nuint256 balanceAfter = _getBalance(makerAssetId);\nuint256 refund = balanceAfter > balanc"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(Exchange|Trading|OrderBook|Settle|Clob|Match|Auction)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '(?i)^_?(matchOrders|matchBuyOrders|matchSellOrders|settleTakerOrder|settleMakerOrders|settleOrders|fillBatch|batchFill|finalizeMatch|matchOrder)$'}, {'function.body_contains_regex': '(refund|leftover|residual|excess)\\s*=\\s*([\\w\\.]+\\.balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\)|_?getBalance\\s*\\([^)]*\\))'}, {'function.body_contains_regex': '(?i)(safeTransfer|_transfer|\\.transfer)\\s*\\([^)]*(taker|takerOrder|order\\.maker|fillRecipient|recipient|to)'}, {'function.body_not_contains_regex': '(balanceBefore|preBalance|priorBalance|snapshotBefore|startingBalance|balancePre|balance0)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — settle-batch-refund-flushes-self-balance: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
