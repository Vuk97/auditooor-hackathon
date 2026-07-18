"""
oracle-cascade-external-call-without-stale-check — generated from reference/patterns.dsl/oracle-cascade-external-call-without-stale-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py oracle-cascade-external-call-without-stale-check.yaml
Source: auditooor-SKILL_ISSUE-219
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OracleCascadeExternalCallWithoutStaleCheck(AbstractDetector):
    ARGUMENT = "oracle-cascade-external-call-without-stale-check"
    HELP = "Function reads from a price oracle and then performs an external call without checking oracle freshness/staleness. If the oracle returns stale or manipulated data, the external call can be exploited to extract value."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/oracle-cascade-external-call-without-stale-check.yaml"
    WIKI_TITLE = "Oracle read followed by external call without staleness check"
    WIKI_DESCRIPTION = "A function that queries a price oracle (latestAnswer, latestRoundData, getPrice, etc.) and subsequently makes an external call (to another contract, token transfer, or DeFi interaction) without validating that the oracle data is fresh. An attacker can exploit stale or manipulated oracle prices to gain an advantage in the external interaction."
    WIKI_EXPLOIT_SCENARIO = "Attacker manipulates the oracle price source (e.g., via a flash loan on a DEX used as price feed). The victim contract reads the manipulated price, then uses it in an external call (swap, liquidation, collateral valuation). Because the contract never checks updatedAt, roundId, or heartbeat, the stale/manipulated price is accepted as valid, allowing the attacker to profit from the distorted valuati"
    WIKI_RECOMMENDATION = "Always validate oracle freshness before using the price in external interactions. Check updatedAt against a maximum acceptable age, verify roundId is non-zero and increasing, and ensure the price is within min/max bounds. For Chainlink: require(block.timestamp - updatedAt < HEARTBEAT, 'stale price')"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(oracle|price|feed|chainlink|pyth|band|api3|redstone|twap|latestAnswer|latestRoundData)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.body_contains_regex': '(latestAnswer|latestRoundData|getPrice|getLatestPrice|consult|observe|getTwap|getSpotPrice|readOracle|_getPrice|_consult|_getLatest)\\s*\\('}, {'function.body_contains_regex': '(\\.call\\s*[\\(\\{]|\\.delegatecall\\s*[\\(\\{]|\\.staticcall\\s*[\\(\\{]|external\\s+(call|function)|transfer\\s*\\(|send\\s*\\()'}, {'function.body_not_contains_regex': '(updatedAt|roundId|timestamp|heartbeat|stale|freshness|age|validity|confidence|minAnswer|maxAnswer|sequencerUp|isStale|isFresh|checkOracle|validatePrice)'}, {'function.body_not_contains_regex': 'require\\s*\\(\\\\s*(updatedAt|timestamp|age|heartbeat)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — oracle-cascade-external-call-without-stale-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
