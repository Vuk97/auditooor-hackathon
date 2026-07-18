"""
crosschain-rebase-no-sequence-number — generated from reference/patterns.dsl/crosschain-rebase-no-sequence-number.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py crosschain-rebase-no-sequence-number.yaml
Source: solodit/sherlock/eco-H2-18610
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CrosschainRebaseNoSequenceNumber(AbstractDetector):
    ARGUMENT = "crosschain-rebase-no-sequence-number"
    HELP = "Cross-chain state-push (rebase / setIndex / setPrice) forwards a snapshot value without a source-side block number, epoch, or sequence number. Failed messages can be manually retried out-of-order to overwrite fresh destination state with an older value."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/crosschain-rebase-no-sequence-number.yaml"
    WIKI_TITLE = "Cross-chain rebase / setIndex without sequence number enables stale-value replay"
    WIKI_DESCRIPTION = "A permissionless relay function captures a mutable state variable on the source chain (inflation multiplier, oracle index, reward rate) and sends it as a cross-domain message. The payload carries only the value itself — no block number, epoch counter, or per-destination nonce — so the destination cannot order messages. Because cross-domain messengers (Optimism, Arbitrum, LayerZero, Hyperlane) expo"
    WIKI_EXPLOIT_SCENARIO = "L1ECOBridge.rebase() is `external` with no auth. Attacker calls it 20 times while inflationMultiplier = 1.0, intentionally starving some messages of L2 gas so they land in `failedMessages`. Over the next months L1 inflation grows to 1.2 via legitimate rebases. Attacker selects an old failedMessage where multiplier = 1.0 and calls `relayMessage` on L2. Because the payload has no timestamp / nonce, "
    WIKI_RECOMMENDATION = "Bake a monotonic counter into the payload: `abi.encode(multiplier, block.number)` or `abi.encode(multiplier, ++rebaseEpoch)`. On the destination, require `require(msg.blockOrEpoch > lastAppliedBlockOrEpoch)` before applying. For LayerZero/Hyperlane, use the channel's nonce + `require(nonce > lastNon"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.body_contains_regex': 'sendCrossDomainMessage|sendMessage\\s*\\(|dispatch\\s*\\(|lzSend\\s*\\(|callRemote'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': 'sendCrossDomainMessage|sendMessage\\s*\\(|dispatch\\s*\\(|lzSend\\s*\\(|callRemote|send\\s*\\(\\s*dstChainId'}, {'function.body_contains_regex': 'abi\\.encode(WithSelector)?\\s*\\([^)]*\\.(selector|rebase|setIndex|setRate|setMultiplier|setPrice|updatePrice|updateIndex)'}, {'function.body_not_contains_regex': 'abi\\.encode[^)]*(block\\.number|block\\.timestamp|nonce|epoch|version|sequence|seqNum|seqNo)'}, {'function.modifiers_not_matching': '(onlyOwner|onlyRole|onlyAdmin|onlyGov)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — crosschain-rebase-no-sequence-number: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
