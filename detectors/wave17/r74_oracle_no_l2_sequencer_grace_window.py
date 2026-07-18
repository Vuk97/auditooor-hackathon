"""
r74-oracle-no-l2-sequencer-grace-window — generated from reference/patterns.dsl/r74-oracle-no-l2-sequencer-grace-window.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r74-oracle-no-l2-sequencer-grace-window.yaml
Source: r74b-cross-firm-cs+oz
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R74OracleNoL2SequencerGraceWindow(AbstractDetector):
    ARGUMENT = "r74-oracle-no-l2-sequencer-grace-window"
    HELP = "L2 contract reads a price feed without enforcing a grace-window delay after sequencer restart; consumers act on stale pre-downtime prices in that window."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r74-oracle-no-l2-sequencer-grace-window.yaml"
    WIKI_TITLE = "Missing L2 sequencer grace-window enforcement on price consumption"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. When an L2 (Arbitrum / Optimism / Base) sequencer restarts after downtime, the underlying aggregator's last-known price is re-served as if fresh. Consumers that only check the sequencer is up (boolean) but not that at least some grace period has elapsed since it came back up operate on known-stale prices during the grace window, enabling MEV"
    WIKI_EXPLOIT_SCENARIO = "Arbitrum sequencer goes down for 2 hours. ETH drops 8% on L1 during the outage. When the sequencer restarts, the on-chain feed still reports the pre-outage price for up to a heartbeat. A bot liquidates under-collateralized positions at the stale (favorable-to-liquidator) price within the first block, before the feed round advances."
    WIKI_RECOMMENDATION = "After verifying the sequencer is up, require that at least GRACE_PERIOD (e.g. 3600 seconds) has passed since `startedAt` on the sequencer uptime feed: `require(block.timestamp - startedAt > GRACE_PERIOD, 'grace')`. Reject price consumption during the grace window. Keep submission_posture NOT_SUBMIT_"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'latestRoundData|AggregatorV3Interface|SequencerUptimeFeed'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': 'latestRoundData\\s*\\(|getAnswer\\s*\\(|getPrice\\s*\\('}, {'function.body_not_contains_regex': 'GRACE_PERIOD|gracePeriod|grace_period|block\\.timestamp\\s*-\\s*startedAt\\s*[<>]|timeSinceUp|sequencerUpAtLeast'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r74-oracle-no-l2-sequencer-grace-window: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
