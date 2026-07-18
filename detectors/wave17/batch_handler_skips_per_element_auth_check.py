"""
batch-handler-skips-per-element-auth-check — generated from reference/patterns.dsl/batch-handler-skips-per-element-auth-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py batch-handler-skips-per-element-auth-check.yaml
Source: auditooor-R73-injective-wall-of-shame-MsgBatchUpdateOrders
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BatchHandlerSkipsPerElementAuthCheck(AbstractDetector):
    ARGUMENT = "batch-handler-skips-per-element-auth-check"
    HELP = "A batch handler iterates multiple sub-order / sub-action arrays calling per-element ValidateBasic on most but skips one array, deferring only to an aggregate (duplicate / sum) check that does not re-run authorization — anyone can embed other-user items in the skipped array."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/batch-handler-skips-per-element-auth-check.yaml"
    WIKI_TITLE = "Batch handler skips per-element ownership validation on one sub-array — anyone can drain"
    WIKI_DESCRIPTION = "The canonical example is Injective's `MsgBatchUpdateOrders.ValidateBasic`: limit orders and cancels call `order.ValidateBasic(sender)` (which internally calls `CheckValidSubaccountIDOrNonce`, the ownership check), but three market-order arrays (`SpotMarketOrdersToCreate`, `DerivativeMarketOrdersToCreate`, `BinaryOptionsMarketOrdersToCreate`) only pass through `ensureNoDuplicateMarketOrders(sender,"
    WIKI_EXPLOIT_SCENARIO = "(1) Attacker creates a worthless token FAKE and a permissionless FAKE/USDT market. (2) Attacker places a limit sell on FAKE/USDT from their own subaccount at an inflated price. (3) Attacker submits MsgBatchUpdateOrders with a market BUY in SpotMarketOrdersToCreate whose `SubaccountId` is VICTIM's subaccount. (4) ValidateBasic iterates Cancel/Limit arrays calling per-element ValidateBasic(sender) ("
    WIKI_RECOMMENDATION = "Always run per-element auth on EVERY sub-array in a batch handler. Factor the loop into one helper: `validateAll(sender, allSubOrders)` that walks every type-specific array and delegates to `subOrder.ValidateBasic(sender)`. Add a meta-invariant test: for each new sub-order type added to the message,"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(ValidateBasic|validateBasic|batch|execute(All|Many|Batch))'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(validateBasic|execute(All|Many|Batch)|multicall|batchCreate|handleBatch|MsgBatch)'}, {'function.body_contains_regex': '(?i)(for\\s+(idx|i)\\s+(range|:=|in)\\s+msg\\.\\w+)'}, {'function.body_contains_regex': '(?i)(ensureNoDuplicate|_validateOnce|sanitize|normalize|ensure\\w+)\\s*\\([^)]*(Market|Order|Item)\\w*\\)'}, {'function.body_not_contains_regex': '(?i)(for\\s+(idx|i)\\s+(range|:=|in)\\s+msg\\.\\w*MarketOrdersToCreate[^}]*ValidateBasic|for\\s+(idx|i)\\s+(range|:=|in)\\s+msg\\.\\w*MarketOrdersToCreate[^}]*CheckValidSubaccount|for\\s+(idx|i)\\s+(range|:=|in)\\s+msg\\.\\w*MarketOrdersToCreate[^}]*require\\s*\\()'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — batch-handler-skips-per-element-auth-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
