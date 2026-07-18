"""
ec-rate-limiter-window-boundary — generated from reference/patterns.dsl/ec-rate-limiter-window-boundary.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ec-rate-limiter-window-boundary.yaml
Source: auditooor-R71-ec-patterns-batch
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EcRateLimiterWindowBoundary(AbstractDetector):
    ARGUMENT = "ec-rate-limiter-window-boundary"
    HELP = "Rate limiter uses fixed-window boundaries (timestamp / WINDOW) instead of a rolling window. Attacker drains the full cap just before window rollover, then drains another full cap immediately after — netting 2× the nominal rate limit."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ec-rate-limiter-window-boundary.yaml"
    WIKI_TITLE = "Rate-limiter window-boundary double-drain (fixed vs rolling window)"
    WIKI_DESCRIPTION = "Function enforces a per-window cap (`usedInWindow[currentWindow] + amount <= MAX`), where `currentWindow = block.timestamp / WINDOW`. At the window boundary (1 sec before next window starts), the cap resets atomically — an attacker who has used the full cap in the current window can issue another `amount == MAX` call one block later, netting 2× the nominal limit in seconds. A correctly-designed sl"
    WIKI_EXPLOIT_SCENARIO = "A cross-chain bridge caps outbound transfers at 1000 ETH/day. `withdraw()` computes `uint256 currentDay = block.timestamp / 1 days` and tracks `dayUsage[currentDay]`. At 23:59:59 UTC, attacker withdraws 999 ETH. At 00:00:01 UTC (2 seconds later, next block), `currentDay` has advanced; `dayUsage[currentDay]` is 0; attacker withdraws another 1000 ETH. Net: 1999 ETH drained in 2 seconds, vs the nomin"
    WIKI_RECOMMENDATION = "Use a sliding-window or token-bucket rate limiter:\n\n```solidity\n// Sliding window: decay linearly\nuint256 dt = block.timestamp - lastUpdate;\nuint256 decayed = used > used * dt / WINDOW ? used - used * dt / WINDOW : 0;\nrequire(decayed + amount <= CAP, \"rate-limited\");\nused = decayed + amount"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'withdraw|burn|redeem|exit|bridgeOut|send[A-Z]|transferOut|unlock|claim'}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.body_contains_regex': '(currentWindow|currentEpoch|currentPeriod|epoch|period)\\s*=\\s*block\\.timestamp\\s*\\/\\s*[A-Z_0-9]+|block\\.timestamp\\s*-\\s*\\(\\s*block\\.timestamp\\s*%\\s*[A-Z_0-9]+\\s*\\)|block\\.timestamp\\s*\\/\\s*(WINDOW|PERIOD|INTERVAL|ONE_DAY|DAY|HOUR)'}, {'function.body_contains_regex': '(used|consumed|emitted|withdrawn)\\s*\\[[^\\]]*\\]|[a-zA-Z_]+Accumulator|if\\s*\\(\\s*[a-zA-Z_.]+\\s*\\+\\s*amount\\s*>\\s*(MAX|CAP|LIMIT)'}, {'function.body_not_contains_regex': '(rollingWindow|slidingWindow|timeDecay|lastWindow\\s*\\*\\s*\\(|windowDecay|linearDecay)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — ec-rate-limiter-window-boundary: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
