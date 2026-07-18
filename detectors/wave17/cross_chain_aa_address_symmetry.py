"""
cross-chain-aa-address-symmetry — generated from reference/patterns.dsl/cross-chain-aa-address-symmetry.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py cross-chain-aa-address-symmetry.yaml
Source: code4arena-2025-11-brix-money-M-03
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CrossChainAaAddressSymmetry(AbstractDetector):
    ARGUMENT = "cross-chain-aa-address-symmetry"
    HELP = "Cross-chain entrypoint hardcodes the destination recipient to `msg.sender` — works for EOAs but silently mis-routes (or loses) tokens for AA / multisig / Safe wallets whose address differs across chains."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/cross-chain-aa-address-symmetry.yaml"
    WIKI_TITLE = "Cross-chain address symmetry assumption breaks AA wallets"
    WIKI_DESCRIPTION = "A cross-chain function (LayerZero OFT unstake, CCIP bridge-and-claim, Axelar cross-call, Wormhole receiver) takes no explicit destination-recipient parameter and instead routes the cross-chain message payload to `msg.sender` on the destination chain (typically encoded as `bytes32(uint256(uint160(msg.sender)))` or via `addressToBytes32(msg.sender)`). Under the implicit 'same user = same address on "
    WIKI_EXPLOIT_SCENARIO = "Alice uses Argent Smart Wallet `0xAAA...` on Ethereum and `0xBBB...` on Optimism (different addresses because Argent's counterfactual deploy includes a salt keyed to first-funding). Alice holds LayerZero-issued OFT tokens on Ethereum. She calls `unstake(100e18)` which internally invokes `_lzSend` with `SendParam.to = addressToBytes32(msg.sender) = bytes32(0xAAA...)`. The payload lands on Optimism "
    WIKI_RECOMMENDATION = "Every cross-chain entrypoint must accept the destination recipient as an explicit parameter: `function unstake(uint256 amount, bytes32 destinationRecipient)`. For UX, offer a client-side resolver that queries the user's wallet on the destination chain before submitting. For protocol-level safety, ma"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'lzCompose|lzReceive|ILayerZero|_lzSend|IOFT|OApp|OAppReceiver|CCIPReceiver|IAxelarExecutable|IWormholeReceiver|MessagingFee|SendParam'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(unstake|withdraw|redeem|claim|bridge|send|transferOut|crossChainSend|fastRedeem|lzSend|compose|bridgeAndCall|remoteDeposit|remoteStake)'}, {'function.body_contains_regex': {'regex': '_lzSend\\s*\\(|lzSend\\s*\\(|endpoint\\.send\\s*\\(|oftSend\\s*\\(|IOFT\\s*\\(.*\\)\\.send|ccipRouter\\.ccipSend|ICCIPRouter|router\\.ccipSend|callContract\\s*\\(|IAxelarGateway'}}, {'function.body_contains_regex': {'regex': 'addressToBytes32\\s*\\(\\s*msg\\.sender|bytes32\\s*\\(\\s*uint256\\s*\\(\\s*uint160\\s*\\(\\s*msg\\.sender|SendParam[^;]+msg\\.sender|to:\\s*msg\\.sender|recipient\\s*=\\s*msg\\.sender|receiver\\s*=\\s*msg\\.sender|composeMsg[^;]+msg\\.sender'}}, {'function.body_not_contains_regex': 'destAddress\\[msg\\.sender\\]|crossChainRecipient\\[msg\\.sender\\]|_resolveRecipient\\s*\\(|destinationOf\\s*\\(|to\\s*!=\\s*address\\(0\\)[\\s\\S]*(_lzSend|send\\s*\\()'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — cross-chain-aa-address-symmetry: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
