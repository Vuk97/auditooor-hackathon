"""
lzcompose-target-missing-authorized-oft-and-sender-check — generated from reference/patterns.dsl/lzcompose-target-missing-authorized-oft-and-sender-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py lzcompose-target-missing-authorized-oft-and-sender-check.yaml
Source: auditooor-R75-nethermind-ccdm-CRITICAL
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LzcomposeTargetMissingAuthorizedOftAndSenderCheck(AbstractDetector):
    ARGUMENT = "lzcompose-target-missing-authorized-oft-and-sender-check"
    HELP = "LayerZero V2 composability lets any oApp call sendCompose on the endpoint, which then permissionlessly forwards to a target's lzCompose. A target that only checks msg.sender==endpoint without also verifying (1) the _from OFT is an authorized token-bridge and (2) the composeFrom() inner sender is a t"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/lzcompose-target-missing-authorized-oft-and-sender-check.yaml"
    WIKI_TITLE = "LayerZero lzCompose target authenticates only the endpoint, not the OFT origin or source sender"
    WIKI_DESCRIPTION = "EndpointV2.sendCompose is permissionless by design — any oApp on the destination chain can queue a compose message, and the endpoint will deliver it to the target. The target's sole protection is its lzCompose handler. A handler that validates msg.sender == endpoint but does not also gate on (a) _from (the delivering OFT contract) matching a pre-registered authorized OFT, and (b) the source-chain "
    WIKI_EXPLOIT_SCENARIO = "CCDM's DepositExecutor.lzCompose only checks msg.sender == LAYER_ZERO_V2_ENDPOINT. Attacker deploys a trivial oApp on the destination chain, calls endpoint.sendCompose with _to=DepositExecutor, and a forged OFTComposeMsgCodec payload claiming amountLD = 10_000e6 USDC bridged from a real user. DepositExecutor credits the attacker's Weiroll wallet. When the campaign owner executes recipes, the attac"
    WIKI_RECOMMENDATION = "In lzCompose, check three things: (1) msg.sender == trusted endpoint, (2) _from is in an allowlist of OFT/token-bridge contracts for the expected token, (3) OFTComposeMsgCodec.composeFrom(_message) equals the registered source-chain peer (e.g., DepositLocker). All three must pass before any accounti"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'lzCompose|ILayerZeroComposer|OFTComposeMsgCodec'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'lzCompose'}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.body_contains_regex': 'msg\\.sender\\s*==\\s*[A-Z_0-9]*LAYER[_A-Z0-9]*ENDPOINT|msg\\.sender\\s*==\\s*endpoint'}, {'function.body_not_contains_regex': '(_from\\s*==|authorizedOFTs\\[_from\\]|composeFrom.*==|tokenToLzV2OFT\\[.*\\]\\s*==\\s*_from)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — lzcompose-target-missing-authorized-oft-and-sender-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
