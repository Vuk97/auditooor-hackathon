"""
c4-router-arbitrary-from-drain — generated from reference/patterns.dsl/c4-router-arbitrary-from-drain.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py c4-router-arbitrary-from-drain.yaml
Source: code4arena/slice_ab-BakerFi
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class C4RouterArbitraryFromDrain(AbstractDetector):
    ARGUMENT = "c4-router-arbitrary-from-drain"
    HELP = "Router `pullToken(from, amount)` pulls via `safeTransferFrom(from, ...)` where `from` is caller-supplied. Any user who approved the router to some amount can be drained by a third party passing their address as `from`."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/c4-router-arbitrary-from-drain.yaml"
    WIKI_TITLE = "Router pulls tokens from arbitrary `from` parameter"
    WIKI_DESCRIPTION = "A router that reads `from` from calldata (not `msg.sender`) and calls `token.safeTransferFrom(from, to, amount)` weaponizes every existing approval. This is the `pullTokensWithPermit`/`vaultDeposit` anti-pattern."
    WIKI_EXPLOIT_SCENARIO = "Alice approves Router for 100 USDC. Mallory calls `Router.pullToken(alice, 100, mallory)`. Router pulls 100 USDC from Alice to Mallory. Any approval is drainable by the first attacker to notice."
    WIKI_RECOMMENDATION = "Require `from == msg.sender`, or take a signed EIP-712 intent from `from` that binds `amount + destination + deadline`."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'Router|pullToken|_pullTokens|permit'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(pullToken|pullTokens|pullTokensWithPermit|vaultDeposit|routeDeposit|swap)'}, {'function.has_param_name_matching': 'from|sender|user|owner'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.body_contains_regex': 'safeTransferFrom\\s*\\(\\s*(\\w*from|\\w*sender|\\w*user|\\w*owner)'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*(\\w*from|\\w*sender|\\w*user|\\w*owner)\\s*==\\s*msg\\.sender|ECDSA\\.recover|IERC20Permit\\s*\\(\\s*\\w+\\s*\\)\\.permit\\s*\\(\\s*\\w*(from|owner|user)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — c4-router-arbitrary-from-drain: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
