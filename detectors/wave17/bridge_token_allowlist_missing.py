"""
bridge-token-allowlist-missing — generated from reference/patterns.dsl/bridge-token-allowlist-missing.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bridge-token-allowlist-missing.yaml
Source: solodit-cluster-cross-cluster-bridge
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BridgeTokenAllowlistMissing(AbstractDetector):
    ARGUMENT = "bridge-token-allowlist-missing"
    HELP = "Bridge receive-side accepts an arbitrary ERC20 address without consulting a token allowlist — a malicious token contract can corrupt bridge state or escrow accounting."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bridge-token-allowlist-missing.yaml"
    WIKI_TITLE = "Bridge token allowlist missing: receive-side trusts caller-supplied token address"
    WIKI_DESCRIPTION = "Token bridges and lock-and-mint controllers must only operate on pre-vetted token addresses. When the receive / finalize function reads an `address token` from the inbound payload and invokes transfer / transferFrom / mint on it without checking an allowlist (whitelist / supportedTokens / isAllowed), an attacker can point the bridge at a contract of their choosing. A reentrant transfer, an ERC-777"
    WIKI_EXPLOIT_SCENARIO = "An attacker deploys MaliciousToken whose transfer callback re-enters the bridge or whose transferFrom reports success without moving tokens. They submit a bridge message naming MaliciousToken as the asset. The bridge credits the attacker as if real funds arrived (accounting is updated), or re-entrancy during the token callback lets the attacker dequeue a second message against the real escrow. Bri"
    WIKI_RECOMMENDATION = "Maintain an explicit `mapping(address => bool) public supportedTokens` (or equivalent) gated by a governance-only setter. On every receive / finalize path, require `supportedTokens[token]` before invoking transfer / transferFrom / mint on that token. Reject unknown tokens and document the allowlist "

    _PRECONDITIONS = [{'contract.has_function_body_matching': 'bridgeToken|receiveTokens|finalizeBridge|_handleBridge'}, {'contract.source_matches_regex': '(?i)(bridge|gateway|messenger|endpoint|OFT|handler|mintFromBridge|finalizeBridge|receiveTokens)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'bridge|bridgeToken|receiveTokens|finalizeBridge|_handleBridge|mintFromBridge|handleTokenBridge'}, {'function.has_param_of_type': 'address'}, {'function.body_not_contains_regex': 'whitelist\\[|allowedToken\\[|isAllowed\\s*\\(|supportedTokens\\[|tokenList\\[|mapping\\s*\\(\\s*address\\s*=>\\s*bool\\s*\\)\\s*public.*[Ww]hite'}, {'function.not_source_matches_regex': '(IERC20\\s+(public\\s+)?immutable\\s+\\w+\\s*;|address\\s+(public\\s+)?immutable\\s+(asset|token|underlying)\\s*;|ITokenRegistry|IAssetRegistry\\.isRegistered|canonicalToken\\s*\\(\\s*\\w+\\s*\\)\\s*==)'}]

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
                info = [f, f" — bridge-token-allowlist-missing: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
