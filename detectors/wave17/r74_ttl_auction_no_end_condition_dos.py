"""
r74-ttl-auction-no-end-condition-dos — generated from reference/patterns.dsl/r74-ttl-auction-no-end-condition-dos.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r74-ttl-auction-no-end-condition-dos.yaml
Source: r74b-cross-firm-cs+oz
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R74TtlAuctionNoEndConditionDos(AbstractDetector):
    ARGUMENT = "r74-ttl-auction-no-end-condition-dos"
    HELP = "NOT_SUBMIT_READY fixture-smoke/source-shape proof only: auction bid path extends `endTime = block.timestamp + ttl` on every bid without a hard end cap, so tiny late bids can keep the auction open indefinitely."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r74-ttl-auction-no-end-condition-dos.yaml"
    WIKI_TITLE = "TTL auction extension has no hard end condition"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. Anti-sniping auction extensions are safe only when the rolling TTL is bounded by an absolute end time. If every bid rewrites `endTime` from `block.timestamp + ttl` with no `hardEnd` / max-duration cap, a bidder can submit minimal bids near the end of each window and keep seller collateral, bidder funds, or settlement state locked indefinitel"
    WIKI_EXPLOIT_SCENARIO = "A collateral auction starts with `endTime = now + 1 hour` and `ttl = 15 minutes`. The bid path accepts any bid over the current high bid and then sets `endTime = block.timestamp + ttl`. An attacker places a tiny increment seconds before expiry, waits until the next near-expiry moment, and repeats. Because there is no `hardEnd`, `maxEndTime`, or final deadline, settlement never becomes reliably rea"
    WIKI_RECOMMENDATION = "Keep the anti-sniping TTL, but cap it with an absolute deadline: `uint256 nextEnd = block.timestamp + ttl; auction.endTime = nextEnd > auction.hardEnd ? auction.hardEnd : nextEnd;`. Reject bids after `hardEnd`, and add tests proving repeated late bids cannot extend the auction past the configured ma"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(auction|bid|ttl|timeToLive|endTime|deadline)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(_?bid|placeBid|submitBid|bidOnAuction|increaseBid|buy)\\w*$'}, {'function.reads_block_timestamp': True}, {'function.body_contains_regex': '(?i)(ttl|timeToLive|bidTtl|extensionWindow|extensionDuration|antiSniping)'}, {'function.body_contains_regex': '(?i)(endTime|deadline|auctionEnd|endsAt|expiresAt)\\s*=\\s*(block\\.timestamp\\s*\\+\\s*(ttl|timeToLive|bidTtl|extensionWindow|extensionDuration)|[^;\\n]*\\+\\s*(ttl|timeToLive|bidTtl|extensionWindow|extensionDuration))'}, {'function.body_not_contains_regex': '(?i)(hardEnd|maxEndTime|finalDeadline|MAX_AUCTION_DURATION|MAX_DURATION|MAX_TTL|auctionStart\\s*\\+\\s*maxDuration|Math\\.min|min\\s*\\(|block\\.timestamp\\s*>\\s*\\w+\\s*\\+\\s*MAX|require\\s*\\([^;]*(hardEnd|maxEndTime|finalDeadline))'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r74-ttl-auction-no-end-condition-dos: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
