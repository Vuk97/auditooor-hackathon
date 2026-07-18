"""
chainlink-price-no-l2-sequencer-check — generated from reference/patterns.dsl/chainlink-price-no-l2-sequencer-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py chainlink-price-no-l2-sequencer-check.yaml
Source: solodit-cluster-L2SEQ
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ChainlinkPriceNoL2SequencerCheck(AbstractDetector):
    ARGUMENT = "chainlink-price-no-l2-sequencer-check"
    HELP = "Chainlink price feed consumed without checking the L2 sequencer-uptime feed. On Arbitrum / Optimism / Base, feeds return stale values during sequencer downtime; consumers must consult the Chainlink L2 Sequencer Uptime Feed and enforce a grace period before trusting the price."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/chainlink-price-no-l2-sequencer-check.yaml"
    WIKI_TITLE = "Chainlink consumer on L2 missing sequencer-uptime check"
    WIKI_DESCRIPTION = "On optimistic rollups (Arbitrum, Optimism, Base) Chainlink price feeds can become stale when the sequencer goes down. Contracts that consume these feeds must first read the AggregatorV2V3Interface L2 Sequencer Uptime Feed, reject writes that occurred while the sequencer was down, and enforce a grace period after recovery. Omitting this check allows liquidations, redemptions, and collateral valuati"
    WIKI_EXPLOIT_SCENARIO = "The L2 sequencer halts for several hours. On restart, the price feed round that was last written before the halt is still the latestRoundData(). A consumer that trusts this value without the sequencer-uptime guard will liquidate, mint, or redeem against a stale price, transferring value from honest users to whoever monitors restart windows."
    WIKI_RECOMMENDATION = "Integrate Chainlink's L2 Sequencer Uptime Feed. Before trusting any price, (1) call latestRoundData() on the uptime feed, (2) revert if the answer is not zero (sequencer down), and (3) enforce a grace period since startedAt before accepting prices. See https://docs.chain.link/data-feeds/l2-sequencer"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': {'regex': 'latestRoundData\\s*\\(\\s*\\)|IAggregatorV3|\\.latestAnswer\\s*\\(\\s*\\)'}}, {'function.body_not_contains_regex': 'sequencer|L2Sequencer|SEQUENCER_UPTIME|uptimeFeed|gracePeriod|SequencerUp'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — chainlink-price-no-l2-sequencer-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
