"""
cross-chain-msg-value-not-validated — generated from reference/patterns.dsl/cross-chain-msg-value-not-validated.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py cross-chain-msg-value-not-validated.yaml
Source: solodit/C0136
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CrossChainMsgValueNotValidated(AbstractDetector):
    ARGUMENT = "cross-chain-msg-value-not-validated"
    HELP = "Cross-chain message handler mints/releases/credits funds based on payload fields without validating the claimed value against caps, locked collateral, or whitelists."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/cross-chain-msg-value-not-validated.yaml"
    WIKI_TITLE = "Cross-chain handler: unvalidated message value enables unbacked fund transfer"
    WIKI_DESCRIPTION = "A cross-chain receive path (handleMessage / _lzReceive / receiveMessage / executeMessage) trusts a value/amount field from the decoded payload and proceeds to mint or release funds on the destination chain without checking it against a corresponding lock on the source chain, an allowed cap, or an asset-specific limit."
    WIKI_EXPLOIT_SCENARIO = "Attacker crafts (or steers a relayer to deliver) a message with amount=uint256.max. The destination contract mints that amount of wrapped tokens / releases native ETH without verifying that any corresponding deposit or escrow exists on the source chain. All TVL is drained."
    WIKI_RECOMMENDATION = "Validate every value/amount field in an inbound cross-chain payload: check against cap, locked balance, per-asset whitelist, and daily limit. For bridges, verify the message also carries a corresponding mint/lock proof and that replay protection keys include (srcChain, srcTxHash, messageId)."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(LayerZero|ILayerZeroReceiver|ILZEndpoint|CCIPReceiver|IAxelarExecutable|Wormhole|IReceiver|IMessageRecipient|Connext|Hyperlane|NonblockingLzApp|OApp|OAppReceiver|Bridge|bridge)'}, {'contract.has_function_body_matching': '(?i)(handleMessage|receiveMessage|_lzReceive|onMessage|executeMessage|receive_from_remote|handle_)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(handleMessage|receiveMessage|_lzReceive|lzReceive|nonblockingLzReceive|_nonblockingLzReceive|onMessage|executeMessage|_executeMessage|ccipReceive|_ccipReceive|handle|handle_|_handle|_executeWithTokens|executeWithToken)\\w*$'}, {'function.body_contains_regex': '(?i)(mint|transfer|safeTransfer|release|credit|_credit|unlock|send|\\.call\\{value)'}, {'function.body_not_contains_regex': '(?i)require\\s*\\(.{0,200}(amount|value|msg\\.value|balance|cap|limit|allowed|whitelist|maxAmount|minAmount|>|<|==)'}, {'function.not_source_matches_regex': '(?i)(super\\._lzReceive|super\\._ccipReceive|super\\._execute|super\\.receiveMessage|NonblockingLzApp\\.\\w+|_nonblockingLzReceive\\s*\\([^)]*\\)\\s*\\{\\s*try|retryMessage\\s*\\(|failedMessages\\s*\\[)'}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — cross-chain-msg-value-not-validated: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
