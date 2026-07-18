"""
queued-bridge-message-stale-yield-overwrite — generated from reference/patterns.dsl/queued-bridge-message-stale-yield-overwrite.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py queued-bridge-message-stale-yield-overwrite.yaml
Source: auditooor-R75-nethermind-uspd-LOW-MEDIUM
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class QueuedBridgeMessageStaleYieldOverwrite(AbstractDetector):
    ARGUMENT = "queued-bridge-message-stale-yield-overwrite"
    HELP = "Cross-chain rate-limited message queues (Wormhole NTT, OP bridge queue) can reorder: a message sent at t0 may execute after a message sent at t1>t0. If the payload carries a snapshotted global parameter (yield factor, exchange rate, conversion index) and the destination blindly writes that parameter"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/queued-bridge-message-stale-yield-overwrite.yaml"
    WIKI_TITLE = "Out-of-order cross-chain rate-limited message overwrites monotonic rate parameter"
    WIKI_DESCRIPTION = "Bridges and OFT managers with rate limiting enqueue messages that exceed the per-epoch throughput cap. The queued message retains the source-chain snapshot of yield factor / exchange rate / index at enqueue time. The destination handler assigns this value to storage on release. If two messages queue and release out of order, or a new non-queued message races past a queued one, the destination stat"
    WIKI_EXPLOIT_SCENARIO = "An attacker bridges 1 token from L1 at t0 when yieldFactor=1.05; rate limit queues it. In the next epoch, other transfers update L2 yieldFactor to 1.08. Attacker now executes the queued message; L2 yieldFactor is set to 1.05. Every USPD holder's balanceOf drops ~3%. DEX-based Aave/Morpho positions collateralized with this token are now liquidatable; attacker liquidates them."
    WIKI_RECOMMENDATION = "On the destination, compare incoming yieldFactor/rate to the current stored value and reject (or only take the max of) older values. Track a source-chain monotonic nonce and require incoming nonce > last-applied nonce for rate updates, even when balance credits are still processed."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(NTTManager|Wormhole|lzReceive|releaseShares|updateYield|yieldFactor|rateContract).*rateLimit|rateLimit.*yieldFactor'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(releaseShares|releaseQueued|redeem|redeemQueued|claim|claimQueued|consume|consumeQueued|handleRateLimit|completeQueued|executeQueued|executeQueuedMessage|lzReceive|_lzReceive)$'}, {'function.body_contains_regex': '(yieldFactor|indexRate|shareRate|exchangeRate|pricePerShare)'}, {'function.body_contains_regex': '(updateL2YieldFactor|setYieldFactor|setRate|updateRate)\\s*\\('}, {'function.body_not_contains_regex': '(require|revert|if).*(yieldFactor|rate)\\s*>(=)?\\s*(currentYieldFactor|lastYieldFactor|storedRate)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — queued-bridge-message-stale-yield-overwrite: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
