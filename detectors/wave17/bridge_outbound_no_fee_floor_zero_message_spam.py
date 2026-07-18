"""
bridge-outbound-no-fee-floor-zero-message-spam — generated from reference/patterns.dsl/bridge-outbound-no-fee-floor-zero-message-spam.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bridge-outbound-no-fee-floor-zero-message-spam.yaml
Source: snowbridge-r109-source-mine-oak-v2-finding-11-and-1
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BridgeOutboundNoFeeFloorZeroMessageSpam(AbstractDetector):
    ARGUMENT = "bridge-outbound-no-fee-floor-zero-message-spam"
    HELP = "Outbound bridge endpoint accepts user-supplied executionFee/destinationFee with no minimum floor and no rejection of empty messages. Attacker can spam zero-fee no-op messages or get assets stranded on the destination by under-paying execution."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bridge-outbound-no-fee-floor-zero-message-spam.yaml"
    WIKI_TITLE = "Outbound bridge endpoint has no minimum-fee floor and no empty-message rejection"
    WIKI_DESCRIPTION = "Outbound cross-chain endpoints typically take user-supplied fee amounts (executionFee for destination XCM/IBC execution, relayerFee for the off-chain relayer bounty). The fees are forwarded as-is to the destination chain. The bug class: the source chain validates only `msg.value >= executionFee + relayerFee` (i.e., fees are paid in native ETH), but does not check `executionFee >= MIN_DEST_EXECUTIO"
    WIKI_EXPLOIT_SCENARIO = "Attacker drives an automated script calling `Gateway.v2_sendMessage('', [], '', 0, 0)` 1000 times per Ethereum block. Each call costs ~50k gas on Ethereum. Total cost: 50M gas/block. Effect on destination Polkadot AssetHub: 1000 fresh outbound nonces appear in OutboundQueue per block; relayers MUST submit MMR proofs for each (since BEEFY signs the OutboundQueue commitment, skipping a nonce is impo"
    WIKI_RECOMMENDATION = "Two enforcements. (1) Reject empty messages: `require(xcm.length > 0 || assets.length > 0, EmptyMessage());`. (2) Enforce a minimum executionFee that scales with destination chain economics — either a constant `MIN_DEST_FEE` updated by governance, or a quote function `quoteExecutionFee(destinationCh"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(sendMessage|sendToken|outbound|bridge.*send|crossChain)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '(?:executionFee|destinationFee|destFee|remoteFee|targetChainFee)'}, {'function.body_contains_regex': 'msg\\.value\\s*[<>]?=?\\s*\\w*[Ff]ee\\s*\\+\\s*\\w*[Ff]ee|msg\\.value\\s*[<>]?=?\\s*\\w*[Ff]ee'}, {'function.body_not_contains_regex': '(?:executionFee|destinationFee|destFee|remoteFee)\\s*>=?\\s*(?:MIN_|minimum|FLOOR_|floor)|require\\s*\\([^)]*[Ff]ee\\s*>=?\\s*\\w*MIN'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*(?:xcm\\.length\\s*>\\s*0|assets\\.length\\s*>\\s*0|\\w*[Ff]ee\\s*>\\s*0)|InvalidEmpty|EmptyMessage'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — bridge-outbound-no-fee-floor-zero-message-spam: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
