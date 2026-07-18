"""
exchange-rate-provider-allowlist-missing — generated from reference/patterns.dsl/exchange-rate-provider-allowlist-missing.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py exchange-rate-provider-allowlist-missing.yaml
Source: defihacklabs/Cork-Protocol-2025-05
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ExchangeRateProviderAllowlistMissing(AbstractDetector):
    ARGUMENT = "exchange-rate-provider-allowlist-missing"
    HELP = "Vault calls `IRateProvider(addr).rate()` where `addr` is either user-supplied or in an unvalidated mapping. No per-asset allowlist binds the provider to the asset, so a rogue provider returns attacker-controlled values."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/exchange-rate-provider-allowlist-missing.yaml"
    WIKI_TITLE = "Exchange rate provider has no allowlist / asset-binding check"
    WIKI_DESCRIPTION = "Contracts that price assets via a pluggable IRateProvider interface must bind the provider to the specific asset or PSM pair. Without registration, any address that implements `rate()` can be used as the oracle. Attacker deploys a malicious ERC1967Proxy, sets it as rate provider (directly or via social engineering / governance), and returns arbitrary exchange rates."
    WIKI_EXPLOIT_SCENARIO = "Cork Protocol 2025-05 ($12M): CorkHook honored IExchangeRateProvider without checking that the provider was registered for the specific PSM asset. Attacker deployed a rogue rate provider, set it via a governance path that did not validate binding, and drained $12M by reporting an inflated rate that let them mint far more CT tokens than collateral backed."
    WIKI_RECOMMENDATION = "Maintain a per-asset `mapping(address asset => address provider)` populated only via a multisig/timelocked setter. At call-time, `require(providerOf[asset] == provider, 'unbound provider')`. Prefer immutable binding set at deployment if the pool is single-asset."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'IRateProvider|IExchangeRateProvider|rateProvider|exchangeRateProvider|IRate'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.body_contains_regex': '\\.rate\\s*\\(\\s*\\)|\\.getRate\\s*\\(\\s*\\)|\\.exchangeRate\\s*\\(\\s*\\)|IRateProvider\\s*\\(|IExchangeRateProvider\\s*\\('}, {'function.body_not_contains_regex': 'allowedProviders|registeredProviders|isApprovedProvider|require\\s*\\(\\s*providerOf\\s*\\[|require\\s*\\(\\s*approvedProvider'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — exchange-rate-provider-allowlist-missing: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
