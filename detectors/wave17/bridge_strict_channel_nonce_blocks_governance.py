"""
bridge-strict-channel-nonce-blocks-governance — generated from reference/patterns.dsl/bridge-strict-channel-nonce-blocks-governance.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bridge-strict-channel-nonce-blocks-governance.yaml
Source: snowbridge-r109-source-mine-oak-v1-finding-5
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BridgeStrictChannelNonceBlocksGovernance(AbstractDetector):
    ARGUMENT = "bridge-strict-channel-nonce-blocks-governance"
    HELP = "Inbound bridge channel uses strict sequential nonce ordering and shares the same channel between high-volume operational commands and emergency governance commands. A single stuck or DoS-spammed operational message head-of-line-blocks governance for an unbounded time."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bridge-strict-channel-nonce-blocks-governance.yaml"
    WIKI_TITLE = "Strict-nonce bridge channel head-of-line-blocks governance commands"
    WIKI_DESCRIPTION = "Cross-chain bridges typically use one of two nonce schemes for inbound message ordering: (a) strict sequential — message N+1 reverts unless message N has been processed, or (b) sparse bitmap — out-of-order messages are accepted as long as each nonce is unused. The bug class targets bridges in scheme (a) where the SAME channel transports both governance/emergency commands (SetOperatingMode, Upgrade"
    WIKI_EXPLOIT_SCENARIO = "Bridge has channels CHANNEL_GOVERNANCE_PRIMARY, CHANNEL_GOVERNANCE_SECONDARY, CHANNEL_ASSET_HUB. Each channel has its own strict inboundNonce. Attacker flips a switch on AssetHub to begin draining funds via a logic bug. Bridge governance immediately submits a SetOperatingMode(Halted) command. The command is queued in CHANNEL_GOVERNANCE_PRIMARY. Meanwhile, the attacker emits 1000 outbound CallContr"
    WIKI_RECOMMENDATION = "Three options. (1) PRIORITY CHANNEL: route governance commands through a dedicated channel that the gateway's `submitV1` checks AHEAD of any other channel each block, with relayer incentive structure adjusted accordingly. (2) GOVERNANCE-EXCLUSIVE NONCE SPACE: even within a shared channel, gate gover"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(channel|inboundQueue|crossChain.*message)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '\\b\\w*nonce\\s*==\\s*\\w*\\.inboundNonce\\s*\\+\\s*1\\b|\\binboundNonce\\s*\\+\\s*1\\s*==\\s*\\w*nonce|require\\s*\\(\\s*\\w*nonce\\s*==\\s*\\w*\\.inboundNonce\\s*\\+\\s*1'}, {'function.body_contains_regex': '(?:Upgrade|SetOperatingMode|setMode|halt|pause)'}, {'function.body_contains_regex': '(?:MintForeign|UnlockNative|sendToken|TransferToken|registerToken|callContract|CallContract)'}, {'function.body_not_contains_regex': 'isGovernanceChannel|GOVERNANCE_PRIMARY_CHANNEL|GOVERNANCE_SECONDARY_CHANNEL|priorityChannel|expressChannel|isPriority|sparseBitmap.*governance|governance[A-Z]\\w*Channel'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — bridge-strict-channel-nonce-blocks-governance: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
