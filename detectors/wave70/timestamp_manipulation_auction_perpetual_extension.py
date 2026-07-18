"""
timestamp-manipulation-auction-perpetual-extension — generated from reference/patterns.dsl/timestamp-manipulation-auction-perpetual-extension.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py timestamp-manipulation-auction-perpetual-extension.yaml
Source: auditooor-batch5-timestamp-recall-gap
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class TimestampManipulationAuctionPerpetualExtension(AbstractDetector):
    ARGUMENT = "timestamp-manipulation-auction-perpetual-extension"
    HELP = "Auction/lock extension resets endTime on every interaction without a hard-cap guard. Attacker places minimal bids to perpetually extend the auction, preventing settlement. Fix: add a hardEnd cap and ensure extension cannot exceed it."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/timestamp-manipulation-auction-perpetual-extension.yaml"
    WIKI_TITLE = "Auction bid extends endTime without a hard-cap guard — perpetual DoS"
    WIKI_DESCRIPTION = "Auctions and timed locks that reset their deadline to block.timestamp + ttl on each bid or interaction are vulnerable to perpetual-extension DoS. Because there is no hard upper bound on the final deadline, a griever can extend the auction indefinitely by placing a minimum-increment bid just before expiry. The pattern appears in NFT auctions, governance voting windows, lock extensions, and Dutch-au"
    WIKI_EXPLOIT_SCENARIO = "An auction runs with ttl=15 minutes and minimum increment=1 wei. The attacker monitors the endTime and places a 1-wei bid 5 seconds before each expiry. Each bid resets endTime to block.timestamp + 15 minutes. The auction never settles. Gas cost to the attacker: 1 wei per 15 minutes; the protocol is blocked indefinitely."
    WIKI_RECOMMENDATION = "Introduce a hardEnd (immutable maximum deadline) set at auction creation. When extending endTime, cap it: `auction.endTime = min(block.timestamp + ttl, auction.hardEnd)`. Alternatively, limit the number of extensions per auction (counter-based TTL reset cap)."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(endTime|auction|ttl|hardEnd|deadlin)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(placeBid|bid|extend|resetTimer|resetDeadline|updateDeadline|extendAuction|extendLock|extendWindow|addBid)'}, {'function.body_contains_regex': 'endTime\\s*=\\s*block\\.timestamp\\s*\\+\\s*\\w+'}, {'function.body_not_contains_regex': '(?:hardEnd|maxEnd|endCap|hardDeadline|maxDeadline|HARD_END|MAX_END|hardLimit|maxTime)\\b'}, {'function.is_mutating': True}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — timestamp-manipulation-auction-perpetual-extension: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
