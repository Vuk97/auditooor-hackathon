"""
glider-uniswap-v4-subscriber-callback-no-posm-check — generated from reference/patterns.dsl/glider-uniswap-v4-subscriber-callback-no-posm-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-uniswap-v4-subscriber-callback-no-posm-check.yaml
Source: hexens-glider/uniswap-v4-subscriber-callbacks-lack-position-mana
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderUniswapV4SubscriberCallbackNoPosmCheck(AbstractDetector):
    ARGUMENT = "glider-uniswap-v4-subscriber-callback-no-posm-check"
    HELP = "Uniswap V4 ISubscriber callbacks (`notifySubscribe`, `notifyUnsubscribe`, `notifyBurn`, `notifyModifyLiquidity`) are callable without validating `msg.sender == PositionManager`. Anyone can forge position events and corrupt subscriber bookkeeping."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-uniswap-v4-subscriber-callback-no-posm-check.yaml"
    WIKI_TITLE = "Uniswap V4 subscriber callbacks missing PositionManager check"
    WIKI_DESCRIPTION = "ISubscriber integrations (reward trackers, external position indexes) accept liquidity-state callbacks from the PositionManager. If the callbacks are not gated to that canonical caller, any user can emit spoofed notifications — crediting themselves with phantom liquidity, wiping out others' recorded positions, or triggering reward accrual they don't own."
    WIKI_EXPLOIT_SCENARIO = "Reward tracker uses `notifySubscribe(tokenId, user)` to start a reward stream. Callback is public. Attacker calls `notifySubscribe(attackerOwnedTokenId, attacker)` on a subscriber that awards 1% of the pool daily. No actual subscription happened on the PositionManager, but the subscriber tracks it as real — rewards flow to attacker."
    WIKI_RECOMMENDATION = "Add `modifier onlyByPosm { require(msg.sender == address(positionManager), \"not posm\"); _; }` and apply it to all ISubscriber callbacks. Reference: Uniswap v4-periphery Subscriber abstract."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'notifySubscribe|notifyUnsubscribe|notifyBurn|notifyModifyLiquidity|ISubscriber'}]
    _MATCH = [{'function.name_matches': '^(notifySubscribe|notifyUnsubscribe|notifyBurn|notifyModifyLiquidity)$'}, {'function.kind': 'external_or_public'}, {'function.has_modifier': {'includes': ['onlyByPosm', 'onlyPositionManager', 'onlyPosm'], 'negate': True}}, {'function.body_not_contains_regex': 'msg\\.sender\\s*==\\s*(address\\()?\\s*(positionManager|posm|POSM|_positionManager|POSITION_MANAGER)|require\\s*\\(\\s*msg\\.sender\\s*==\\s*\\w*[Pp]ositionManager'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-uniswap-v4-subscriber-callback-no-posm-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
