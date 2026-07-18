"""
r94-loop-cross-chain-destination-accepts-out-of-sequence-inbound-nonce — generated from reference/patterns.dsl/r94-loop-cross-chain-destination-accepts-out-of-sequence-inbound-nonce.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-cross-chain-destination-accepts-out-of-sequence-inbound-nonce.yaml
Source: kelp-rseth-exploit-2026-04-18-banteg-postmortem
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopCrossChainDestinationAcceptsOutOfSequenceInboundNonce(AbstractDetector):
    ARGUMENT = "r94-loop-cross-chain-destination-accepts-out-of-sequence-inbound-nonce"
    HELP = "r94-loop-cross-chain-destination-accepts-out-of-sequence-inbound-nonce"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-cross-chain-destination-accepts-out-of-sequence-inbound-nonce.yaml"
    WIKI_TITLE = "r94-loop-cross-chain-destination-accepts-out-of-sequence-inbound-nonce"
    WIKI_DESCRIPTION = "r94-loop-cross-chain-destination-accepts-out-of-sequence-inbound-nonce"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-cross-chain-destination-accepts-out-of-sequence-inbound-nonce"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(LayerZero|Endpoint|Bridge|OFT|CrossChain|LzReceive)'}]
    _MATCH = [{'function.name_matches': '(?i)^(lzReceive|_lzReceive|handleMessage|receiveMessage|onMessageReceived)$'}, {'function.source_matches_regex': '(\\bnonce\\b\\s*[,:=]|params\\.nonce|message\\.nonce|origin\\.nonce)'}, {'function.not_source_matches_regex': '(require\\s*\\(\\s*\\w*nonce\\s*==\\s*\\w*(expectedNonce|lastNonce)\\s*\\+\\s*1|lastNonce\\s*=\\s*\\w*nonce|sourceOutboundNonce|nextNonce\\s*=\\s*\\w*nonce\\s*\\+\\s*1|strictSequenceCheck|enforceMonotonicNonce|nonce\\s*==\\s*lastNonce\\s*\\+\\s*1)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r94-loop-cross-chain-destination-accepts-out-of-sequence-inbound-nonce: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
