"""
chainlink-round-id-zero-not-checked — generated from reference/patterns.dsl/chainlink-round-id-zero-not-checked.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py chainlink-round-id-zero-not-checked.yaml
Source: solodit-cluster-CL-ROUNDID-ZERO
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ChainlinkRoundIdZeroNotChecked(AbstractDetector):
    ARGUMENT = "chainlink-round-id-zero-not-checked"
    HELP = "Chainlink latestRoundData consumed without asserting roundId != 0. On fresh or migrating aggregators the returned roundId can be zero, which is a known uninitialized-feed signal; consumers that skip this check will read a stale or uninitialized answer as if it were live."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/chainlink-round-id-zero-not-checked.yaml"
    WIKI_TITLE = "Chainlink consumer missing roundId != 0 validation"
    WIKI_DESCRIPTION = "AggregatorV3Interface.latestRoundData returns (roundId, answer, startedAt, updatedAt, answeredInRound). A roundId of zero indicates the aggregator has not yet been written to after a migration or proxy switch, or that the feed is misconfigured. Consumers that destructure the tuple and use `answer` directly — without require(roundId != 0) or require(roundId >= answeredInRound) — can accept a comple"
    WIKI_EXPLOIT_SCENARIO = "A protocol upgrades a Chainlink aggregator proxy to a fresh implementation during a planned migration. For a short window the proxy points at an underlying aggregator whose first round has not yet been filled and roundId returns zero. A consumer contract reads latestRoundData, skips the roundId check, and values collateral (or settles liquidations) against the zero-initialized answer. An attacker "
    WIKI_RECOMMENDATION = "Immediately after destructuring latestRoundData, `require(roundId != 0, \"stale roundId\")` and `require(roundId >= answeredInRound, \"stale round\")`. Combine with a staleness check on `updatedAt` and — for L2 deployments — the L2 Sequencer Uptime Feed guard."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'AggregatorV3Interface|AggregatorV2V3Interface|ChainlinkAggregator|FeedRegistry|IPriceFeed|IOracle|PriceOracle|latestRoundData|latestAnswer'}, {'contract.has_state_var_matching': 'oracle|priceFeed|aggregator|chainlink'}]
    _MATCH = [{'function.body_contains_regex': {'regex': 'latestRoundData\\s*\\(\\s*\\)'}}, {'function.body_contains_regex': {'regex': '(answer|price|latestPrice|roundId)\\s*(=|:=|,)|return\\s*\\(?\\s*(answer|uint256\\s*\\(\\s*answer|price)'}}, {'function.body_not_contains_regex': 'roundId\\s*!=\\s*0|require\\s*\\(\\s*roundId\\s*>\\s*0|_roundId\\s*\\)\\s*\\{[^}]*require|roundId\\s*>=?\\s*answeredInRound'}, {'function.not_source_matches_regex': '_validateRound\\s*\\(|_getPriceWithSanityChecks|_chainlinkSafeRead|MockAggregator|MockChainlink|MockV3Aggregator|contract\\s+Mock\\w*Aggregator'}]

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
                info = [f, f" — chainlink-round-id-zero-not-checked: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
