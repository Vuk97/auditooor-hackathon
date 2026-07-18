"""
glider-erc2771-multicall-sender-spoof — generated from reference/patterns.dsl/glider-erc2771-multicall-sender-spoof.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-erc2771-multicall-sender-spoof.yaml
Source: hexens-glider/erc-2771-msg-sender-address-forgery-bug
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderErc2771MulticallSenderSpoof(AbstractDetector):
    ARGUMENT = "glider-erc2771-multicall-sender-spoof"
    HELP = "Contract uses ERC-2771 `_msgSender()` for authentication AND exposes a public `multicall`/`batch` with `delegatecall` and no access control. An attacker delegatecalls through multicall with arbitrary last-20-bytes of calldata, impersonating any address."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-erc2771-multicall-sender-spoof.yaml"
    WIKI_TITLE = "ERC-2771 + unprotected multicall = arbitrary sender spoof"
    WIKI_DESCRIPTION = "ERC-2771 reads the trailing 20 bytes of calldata as the real sender when msg.sender is a trusted forwarder. If the contract's own multicall does a delegatecall, msg.sender inside the inner call is address(this), satisfying common `msg.sender == address(this)` and `isTrustedForwarder` checks — and the inner _msgSender() returns the attacker-controlled trailing calldata bytes. This is the OpenZeppel"
    WIKI_EXPLOIT_SCENARIO = "Token has `_transferOwnership(_msgSender())` semantics via 2771. Contract exposes `multicall(bytes[] calldata data)` which loops `address(this).delegatecall(data[i])`. Attacker calls `multicall([abi.encodeCall(transferOwnership, (attacker)) . appendedAttackerAddress])` — inner delegatecall reads the appended 20 bytes as sender, becomes owner."
    WIKI_RECOMMENDATION = "Either (a) do not combine ERC-2771 context with arbitrary multicall, (b) require multicall callers are not the trusted forwarder, or (c) strip trailing calldata in the multicall before delegatecalling. OpenZeppelin v4.9+ patched this in ERC2771Context."

    _PRECONDITIONS = [{'contract.source_matches_regex': '_msgSender\\s*\\(\\)|ERC2771|trustedForwarder|isTrustedForwarder'}, {'contract.has_function_body_matching': 'delegatecall|Address\\.functionDelegateCall|multicall\\s*\\('}]
    _MATCH = [{'function.name_matches': '^(multicall|batch|aggregate|multiDelegatecall)$'}, {'function.kind': 'external_or_public'}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.body_contains_regex': 'delegatecall|functionDelegateCall'}, {'function.body_not_contains_regex': 'onlyTrustedForwarder|isTrustedForwarder\\s*\\(\\s*msg\\.sender|onlyOwner|msg\\.sender\\s*==\\s*trustedForwarder'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-erc2771-multicall-sender-spoof: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
