"""
can-minout-checked-after-state-mutation — generated from reference/patterns.dsl/can-minout-checked-after-state-mutation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py can-minout-checked-after-state-mutation.yaml
Source: cantina/2024-2025-slippage-post-mutate-class
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CanMinoutCheckedAfterStateMutation(AbstractDetector):
    ARGUMENT = "can-minout-checked-after-state-mutation"
    HELP = "Slippage `minOut` / `minShares` check happens AFTER `_burn` / `_mint` / balance mutation — on non-atomic callers the state change persists despite a failed slippage bound, or the user simply loses their shares."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/can-minout-checked-after-state-mutation.yaml"
    WIKI_TITLE = "Slippage check enforced after irreversible state mutation"
    WIKI_DESCRIPTION = "Slippage parameters must gate a function BEFORE any state mutation, not after. When `minOut` is enforced at the end of the call, three failure modes arise: (1) the state mutation (burn/mint/transfer) has already happened by the time the revert fires — on non-atomic executors (EntryPoint, try/catch wrappers, signature-delegated flows) the mutation can be extracted and stick; (2) the user pays gas f"
    WIKI_EXPLOIT_SCENARIO = "A vault's `redeem(shares, minOut)` burns shares → computes `assetsOut = shares * totalAssets / totalSupply` → transfers assets → finally `require(assetsOut >= minOut)`. A sandwich bot moves the price between tx broadcast and inclusion; the redeem reverts on the slippage line AFTER the burn. On a protocol with an `EntryPoint` relayer that catches the revert, the burn persists on-chain while the use"
    WIKI_RECOMMENDATION = "Enforce slippage at the top of the function against a view-computed preview: `uint256 previewOut = previewRedeem(shares); require(previewOut >= minOut, \"slippage\"); _burn(caller, shares); _transfer(asset, caller, previewOut);`. Use the ERC4626 preview* pattern. Never place `require(... >= minOut)`"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'minOut|minShares|minAmount|slippage'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_param_name_matching': '(?i)(minOut|minShares|minAmount|minReceived|amountOutMin)'}, {'function.body_contains_regex': '(require|revert\\s+\\w+|if\\s*\\([^)]*<)\\s*[^;]*(minOut|minShares|minAmount|minReceived|amountOutMin)'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': '(_burn|_mint|balanceOf\\[|totalSupply\\s*-|totalSupply\\s*\\+|shares\\s*-=|shares\\s*\\+=)'}, {'function.body_not_contains_regex': 'require\\s*\\([^)]*(>=|>)\\s*min(Out|Shares|Amount|Received)\\s*\\)[\\s\\S]*?(_burn|_mint)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — can-minout-checked-after-state-mutation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
