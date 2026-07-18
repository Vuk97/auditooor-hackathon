"""
perp-signature-missing-oracle-id-replay-across-feeds — generated from reference/patterns.dsl/perp-signature-missing-oracle-id-replay-across-feeds.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py perp-signature-missing-oracle-id-replay-across-feeds.yaml
Source: auditooor-R73-fixdiff-mined-mux3-protocol-31473d705b
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PerpSignatureMissingOracleIdReplayAcrossFeeds(AbstractDetector):
    ARGUMENT = "perp-signature-missing-oracle-id-replay-across-feeds"
    HELP = "Signed price-push payload does not include the oracle/feed id. Signatures are valid across all feeds of the same contract — attacker can cross-feed replay a BTC signature onto a USDC market."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/perp-signature-missing-oracle-id-replay-across-feeds.yaml"
    WIKI_TITLE = "Signed price push omits oracleId: cross-feed signature replay"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: this row proves only the owned Mux-style `setPrice` shape where the signed digest binds `block.chainid`, contract, `sequence`, `price`, and timestamp but omits the oracle/feed id. A replayable signature for one feed can be forwarded onto another feed managed by the same contract. NOT_SUBMIT_READY."
    WIKI_EXPLOIT_SCENARIO = "(1) Oracle signer produces a signed update: `{ chainid=42161, contract=0xAA, sequence=100, price=65_000e8, timestamp=T }` for BTC feed. (2) Attacker intercepts the raw signature (public mempool or relayer). (3) Attacker calls `MuxPriceProvider.setPrice(feedId=USDC, signedPayload, signature)` — verifier hashes without feedId, signature validates. (4) Oracle writes $65_000 as USDC mark price. (5) At"
    WIKI_RECOMMENDATION = "Every signed oracle payload MUST bind to the feed it represents: include `oracleId`, `feedId`, `priceId`, or `marketId` as the first hashed field. Cross-check: recover signer, then assert `recoveredFeedId == expectedFeedId`. Keep this row NOT_SUBMIT_READY until evidence expands beyond the owned fixt"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?s)(MuxPriceProvider|PriceProvider|PushOracle|setPrice|pushPrice).*(signature|signedMessage|ecrecover|ECDSA\\.recover)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(setPrice|pushPrice|updatePrice|submitPrice|_verifySignature|_verifyOracle)'}, {'function.body_contains_regex': '(abi\\.encodePacked|abi\\.encode)\\s*\\([^)]*block\\.chainid[^)]*(sequence|nonce)[^)]*(price|value)'}, {'function.body_not_contains_regex': '(abi\\.encodePacked|abi\\.encode)\\s*\\([^)]*(oracleId|feedId|priceId|marketId)[^)]*block\\.chainid'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.body_contains_regex': '(ecrecover|ECDSA\\.recover|isValidSignature)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — perp-signature-missing-oracle-id-replay-across-feeds: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
