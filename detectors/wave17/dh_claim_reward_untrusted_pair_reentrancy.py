"""
dh-claim-reward-untrusted-pair-reentrancy — generated from reference/patterns.dsl/dh-claim-reward-untrusted-pair-reentrancy.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py dh-claim-reward-untrusted-pair-reentrancy.yaml
Source: defihacklabs-2024-11/DeltaPrime
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DhClaimRewardUntrustedPairReentrancy(AbstractDetector):
    ARGUMENT = "dh-claim-reward-untrusted-pair-reentrancy"
    HELP = "claimReward/harvest accepts a caller-supplied pair/pool/adapter address and makes external calls into it without allowlisting and without a reentrancy guard. The attacker's fake pair re-enters the account to bypass the end-of-call solvency check."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/dh-claim-reward-untrusted-pair-reentrancy.yaml"
    WIKI_TITLE = "Reward-claim with caller-supplied pair enables reentrancy and collateral conversion"
    WIKI_DESCRIPTION = "SmartLoan / margin-account pattern: a public `claimReward(address pair, ...)` (or `harvest`, `collectFees`) takes a pool/pair address as a parameter and invokes a reward interface on it. The contract does not validate that `pair` is a registered pool, and it does not apply a reentrancy guard. The attacker supplies a contract whose `claim(...)` callback re-enters the SmartLoan (e.g. `wrapNativeToke"
    WIKI_EXPLOIT_SCENARIO = "DeltaPrime (Nov 2024, $4.75M): attacker created an attacker-controlled SmartLoan, flash-loaned WETH, deposited ETH as collateral, then called `claimReward(fakePair, [0])`. The SmartLoan forwarded to `fakePair.claim(...)`, which re-entered the SmartLoan and called `wrapNativeToken(address(this).balance)` — converting the (borrowed) ETH into WETH and recognising it as reward, letting the attacker wi"
    WIKI_RECOMMENDATION = "(1) Require the `pair` argument to be registered in a protocol whitelist before any external call. (2) Apply `nonReentrant` to claim/harvest entrypoints that issue external callbacks. (3) Perform the solvency check DURING each external interaction, not only at the end of the top-level call."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'claimReward|harvest|collectFees|getReward\\s*\\('}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(claimReward|claimRewards|harvest|collectFees|getReward|getRewards)$'}, {'function.has_param_name_matching': 'pair|pool|adapter|strategy|gauge|source|market'}, {'function.has_param_of_type': 'address'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': '\\b(pair|pool|adapter|strategy|gauge|source|market)\\b\\s*\\.(claim|call|getReward|getRewardTokens|getLBHooksParameters|balanceOf|harvest)\\s*\\('}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*(whitelist|allowlist|approved|isRegistered|supported)\\[|onlyApprovedPair|onlyWhitelisted|trustedPair|revert\\s+Not(?:Whitelisted|Approved|Registered)'}, {'function.body_not_contains_regex': 'nonReentrant|ReentrancyGuard|_NOT_ENTERED'}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — dh-claim-reward-untrusted-pair-reentrancy: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
