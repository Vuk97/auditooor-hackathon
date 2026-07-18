"""
monotonic-counter-strict-gt-allows-replay-at-equal — generated from reference/patterns.dsl/monotonic-counter-strict-gt-allows-replay-at-equal.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py monotonic-counter-strict-gt-allows-replay-at-equal.yaml
Source: auditooor-R107-thegraph-Trust-M-10
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MonotonicCounterStrictGtAllowsReplayAtEqual(AbstractDetector):
    ARGUMENT = "monotonic-counter-strict-gt-allows-replay-at-equal"
    HELP = "Replay protection on signed messages uses `require(msg.fieldX > storage.lastFieldX)` and then assigns `storage.lastFieldX = msg.fieldX`. Two distinct signed messages with the SAME `fieldX` both pass the strict-greater-than check, allowing exact-equal-value replay. The bug typically lurks behind a si"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/monotonic-counter-strict-gt-allows-replay-at-equal.yaml"
    WIKI_TITLE = "Strict `>` replay guard against monotonic counter allows exact-equal replay"
    WIKI_DESCRIPTION = "Contracts that consume signed off-chain messages — payment receipts, oracle attestations, batch claims, RAVs — frequently use a single per-account 'last seen' counter to enforce monotonicity rather than tracking individual message hashes in a `consumed` mapping. The naive form `require(msg.seq > last); last = msg.seq;` is vulnerable: two messages with `msg.seq == last` pass the strict-greater-than"
    WIKI_EXPLOIT_SCENARIO = "A payment relay accepts off-chain RAVs (Receipt Aggregate Vouchers) signed by the payer. Each RAV has a `timestampN` field representing the cumulative billing snapshot. The relay enforces `require(rav.timestampN > lastCollected[payer][provider])`. The signer signs RAV1 with timestampN=1700000000 covering invoices 1-5 worth $100; the provider collects, `lastCollected = 1700000000`. The signer then "
    WIKI_RECOMMENDATION = "Either (1) use `>=` plus a per-(payer, provider, timestampN) `consumed[hash]` flag to reject exact replays, (2) use a strictly-incrementing per-payer nonce instead of a timestamp, or (3) use `lastCollected` as a >= comparison and have the signed message include both `prev` and `next` so the chain is"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': '(?i)^_?(collect|claim|consume|settle|verify|process|redeem|cashOut|payOut|submit|push)\\w*$'}, {'function.body_contains_regex': '\\brequire\\s*\\(\\s*\\w+(?:\\.\\w+)?\\s*>\\s*\\w+(?:\\.\\w+)?\\s*\\[\\s*[^\\]]+\\s*\\]\\s*[,)]'}, {'function.body_contains_regex': '\\w+\\s*\\[\\s*[^\\]]+\\s*\\]\\s*=\\s*\\w+(?:\\.\\w+)?\\s*;'}, {'function.body_not_contains_regex': '(?i)(>=\\s*\\w+(?:\\.\\w+)?\\s*\\[|consumed\\s*\\[|nonces\\s*\\[\\s*[^\\]]+\\s*\\]\\s*\\+\\+|usedSig\\s*\\[)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — monotonic-counter-strict-gt-allows-replay-at-equal: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
