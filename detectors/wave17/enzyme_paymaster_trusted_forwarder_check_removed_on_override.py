"""
enzyme-paymaster-trusted-forwarder-check-removed-on-override — generated from reference/patterns.dsl/enzyme-paymaster-trusted-forwarder-check-removed-on-override.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py enzyme-paymaster-trusted-forwarder-check-removed-on-override.yaml
Source: auditooor-R76-immunefi-enzyme-$400k
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EnzymePaymasterTrustedForwarderCheckRemovedOnOverride(AbstractDetector):
    ARGUMENT = "enzyme-paymaster-trusted-forwarder-check-removed-on-override"
    HELP = "Override of a GSN/meta-tx function drops the parent's isTrustedForwarder / forwarder whitelist check. Any contract can now impersonate signed calls and drain the paymaster."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/enzyme-paymaster-trusted-forwarder-check-removed-on-override.yaml"
    WIKI_TITLE = "Override drops isTrustedForwarder check, letting any contract act as relay forwarder"
    WIKI_DESCRIPTION = "GSN-based paymasters and ERC-2771 consumers rely on `_msgSender()` returning the decoded signer only when the tx is routed through a whitelisted trusted forwarder. A child contract overrides the entrypoint (`preRelayedCall`, `_msgSender`, `validateAndAuthorize`) and inadvertently removes the `require(isTrustedForwarder(msg.sender))` guard. Any contract can now craft a fake relay call, forge `msg.d"
    WIKI_EXPLOIT_SCENARIO = "Enzyme's GasRelayPaymasterLib overrode the relay entrypoint and lost the trusted-forwarder check. Attacker deploys a malicious forwarder, submits `relayCall` with inflated pctRelayFee/baseRelayFee, and drains the paymaster which auto-tops-up from the Vault. $400k bounty."
    WIKI_RECOMMENDATION = "When overriding GSN hooks, always re-assert `require(isTrustedForwarder(msg.sender))` or call `super.xxx()` first. Add a Slither/semgrep rule: any override of `_msgSender`, `preRelayedCall`, or `acceptRelayedCall` that does not reference `isTrustedForwarder` is flagged. Better — use OZ's ERC2771Cont"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.inherits_gsn_or_access_base': True}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)relayCall|preRelayedCall|acceptRelayedCall|_msgSender|validateAndAuthorize'}, {'function.has_modifier': 'override'}, {'function.body_not_contains_regex': '(?i)isTrustedForwarder\\s*\\(\\s*msg\\.sender\\s*\\)|_trustedForwarder\\s*==\\s*msg\\.sender|require\\s*\\([^)]*forwarder'}, {'function.parent_contains_regex': '(?i)isTrustedForwarder|_trustedForwarder'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — enzyme-paymaster-trusted-forwarder-check-removed-on-override: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
