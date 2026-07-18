"""
fees-from-supply-based-accounting-underpay-on-sell-loop — generated from reference/patterns.dsl/fees-from-supply-based-accounting-underpay-on-sell-loop.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fees-from-supply-based-accounting-underpay-on-sell-loop.yaml
Source: auditooor-R75-code4rena-2024-01-curves-1495
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FeesFromSupplyBasedAccountingUnderpayOnSellLoop(AbstractDetector):
    ARGUMENT = "fees-from-supply-based-accounting-underpay-on-sell-loop"
    HELP = "Holder-fee is credited per-trade using current totalSupply — selling 1 token at a time yields less fees than batch sells because totalSupply shifts per iteration."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fees-from-supply-based-accounting-underpay-on-sell-loop.yaml"
    WIKI_TITLE = "Per-trade fee distribution uses live totalSupply, giving loopers a discount on holder fees"
    WIKI_DESCRIPTION = "`FeeSplitter.addFees(token)` computes `data.cumulativeFeePerToken += msg.value * PRECISION / totalSupply(token)`. A user selling 100 tokens in one call pays fees using totalSupply at time-of-sell. A contract that loops and sells 1 at a time causes totalSupply to shrink each iteration. Because fee calculation uses getSellPrice (bonding curve) which also depends on supply, the total aggregate fee en"
    WIKI_EXPLOIT_SCENARIO = "Alice holds 100 tokens out of 121 total. She sells all in one call: 1.018 ETH of holder fees accrue. Alternatively Alice deploys a contract that sells 1 at a time in a loop: only 0.37 ETH of holder fees accrue. Alice receives the same ETH back either way, but pool holders lose ~0.65 ETH of fee accrual."
    WIKI_RECOMMENDATION = "Compute holder fees using the pre-trade (or post-trade) supply consistently, and apply the entire trade as one settlement. Alternatively, checkpoint fee-per-share on every supply change, not per-msg.value. Add a fuzz test: selling X tokens in 1 call vs X calls must yield the same cumulativeFeePerTok"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)addFees|distributeFees|_distributeHolderFees'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.body_contains_regex': '(?i)totalSupply\\s*\\(|totalSupply\\s*\\['}, {'function.body_contains_regex': '(?i)cumulativeFeePerToken\\s*\\+=|accFeePerShare\\s*\\+='}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.body_contains_regex': '(?i)msg\\.value\\s*\\*\\s*PRECISION\\s*/\\s*totalSupply|amount\\s*\\*\\s*\\w+\\s*/\\s*totalSupply\\('}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fees-from-supply-based-accounting-underpay-on-sell-loop: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
