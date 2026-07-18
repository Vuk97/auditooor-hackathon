"""
oracle-staleness-not-checked — generated from reference/patterns.dsl/oracle-staleness-not-checked.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py oracle-staleness-not-checked.yaml
Source: solodit/chainlink-stale-price-class
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OracleStalenessNotChecked(AbstractDetector):
    ARGUMENT = "oracle-staleness-not-checked"
    HELP = "Function consumes a Chainlink oracle price via latestRoundData()/getPrice() but does not validate the updatedAt timestamp or answeredInRound round-id — stale prices propagate into protocol accounting during feed outages."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/oracle-staleness-not-checked.yaml"
    WIKI_TITLE = "Chainlink oracle staleness not checked"
    WIKI_DESCRIPTION = "The function reads a price from a Chainlink-style feed (latestRoundData, getPrice, _fetchPrice) but never compares updatedAt against block.timestamp nor enforces answeredInRound >= roundId. When the feed stalls (sequencer outage, aggregator freeze, heartbeat miss), the last cached answer is still returned and the protocol will price assets on data that may be hours or days old. Borrow, liquidation"
    WIKI_EXPLOIT_SCENARIO = "Chainlink ETH/USD feed freezes at $3,800 during a global sequencer incident. Market price drops to $2,900 over the next 45 minutes. Because the lending pool's _getCollateralPrice() only reads (,answer,,,) = feed.latestRoundData() without checking updatedAt, every borrow during the outage is priced off the stale $3,800 number. An attacker borrows at the inflated collateral value and walks away when"
    WIKI_RECOMMENDATION = "After every latestRoundData() call, require(block.timestamp - updatedAt <= stalenessThreshold) with a threshold derived from the feed's heartbeat, and require(answeredInRound >= roundId) to reject feeds that stopped publishing. Also enforce answer > 0 and handle L2 sequencer uptime feeds where appli"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(oracle|priceFeed|aggregator|chainlinkFeed)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': {'regex': '(latestRoundData\\s*\\(|getPrice\\s*\\(|_getPrice\\s*\\(|_fetchPrice\\s*\\()'}}, {'function.body_not_contains_regex': 'block\\.timestamp\\s*-\\s*updatedAt|block\\.timestamp\\s*<=?\\s*updatedAt|\\bupdatedAt\\s*\\+\\s*\\w+|answeredInRound\\s*(>=|<)\\s*roundId|stalenessThreshold'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — oracle-staleness-not-checked: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
