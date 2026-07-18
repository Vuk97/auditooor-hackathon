"""
beanstalk-convert-accepts-arbitrary-well-address — generated from reference/patterns.dsl/beanstalk-convert-accepts-arbitrary-well-address.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py beanstalk-convert-accepts-arbitrary-well-address.yaml
Source: auditooor-R76-immunefi-beanstalk-$1.1M
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BeanstalkConvertAcceptsArbitraryWellAddress(AbstractDetector):
    ARGUMENT = "beanstalk-convert-accepts-arbitrary-well-address"
    HELP = "convert() decodes a pool/Well address from user bytes and calls into it without verifying the address is registered. Attacker supplies a fake pool that returns fromAmount=0 and a huge output — free token extraction."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/beanstalk-convert-accepts-arbitrary-well-address.yaml"
    WIKI_TITLE = "Convert/swap trusts user-supplied pool address without registry check"
    WIKI_DESCRIPTION = "A function that performs cross-asset conversion (BEAN ↔ LP, collateral ↔ debt) decodes its target pool address from a caller-supplied bytes blob. The pool is then queried for quote/amount values that drive the output transfer. No whitelist check is performed on the decoded address. An attacker deploys a malicious pool that returns zero `fromAmount` (so `_withdrawTokens` has nothing to pull) and a "
    WIKI_EXPLOIT_SCENARIO = "Beanstalk's pipelineConvert decoded a `wellLp` address from user input, called `lpToPeg()` on it, and used the returned amount as withdraw authorization. A fake Well returned `(0, beanBalanceOfBeanstalk)` — the Diamond paid out every BEAN in the silo without withdrawing any LP. $1.1M+ bounty."
    WIKI_RECOMMENDATION = "Validate every pool/Well/adapter address against an on-chain registry before any external call: `require(wellRegistry.isWell(wellLp))`. Additionally require `fromAmount > 0` and `outputAmount <= cappedMax`. Treat any address decoded from calldata as untrusted."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_pool_registry': True}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^convert\\w*|swap\\w*|pipelineConvert|execute\\w*'}, {'function.body_contains_regex': '(?i)abi\\.decode\\([^)]*address[^)]*\\)|decode\\w*Params.*address'}, {'function.body_contains_external_call_to_user_supplied_addr': True}, {'function.body_not_contains_regex': '(?i)isWhitelisted\\s*\\(|registry\\.isPool|wellRegistry\\.contains|WellRegistered|require\\s*\\([^)]*wells\\s*\\[|isValidWell\\('}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — beanstalk-convert-accepts-arbitrary-well-address: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
