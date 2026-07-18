"""
r74-auth-deauthorized-keeps-shares — generated from reference/patterns.dsl/r74-auth-deauthorized-keeps-shares.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r74-auth-deauthorized-keeps-shares.yaml
Source: r74b-cross-firm-tob+cs
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R74AuthDeauthorizedKeepsShares(AbstractDetector):
    ARGUMENT = "r74-auth-deauthorized-keeps-shares"
    HELP = "deauthorize()/removeFromWhitelist() flips the permission flag but does not force-exit the user's existing share balance; de-permitted users continue accruing yield."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r74-auth-deauthorized-keeps-shares.yaml"
    WIKI_TITLE = "Deauthorized user retains vault shares after whitelist removal"
    WIKI_DESCRIPTION = "Permissioned vaults (money-market funds, RWA tokens, KYC-gated yield products) gate `deposit` and `transfer` on a whitelist but do not force-exit a user when the whitelist flag is revoked. The user's shares remain; the yield accrual continues (since accrual reads totalSupply and shares[user], both of which are unchanged); transfer paths may or may not block (depending on whether the transfer-side "
    WIKI_EXPLOIT_SCENARIO = "A money-market fund regulated in a TradFi jurisdiction revokes a user after a sanctions update. Their shares are not burned. The user is blocked from depositing more but continues to collect daily-accrued interest via the per-share index mechanism. After six months the compliance team notices — by which time the user has also transferred shares OTC to another whitelisted entity, bypassing the revo"
    WIKI_RECOMMENDATION = "deauthorize() should atomically force-redeem the user's balance to cash (or a specified recovery address): `uint shares = balanceOf(user); _burn(user, shares); _transfer(cashAsset, recoveryAddress, shares * pricePerShare);`. Additionally, block transfers when EITHER from OR to is not whitelisted (do"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)\\b(whitelist|allowlist|authorized|permitted|kyc|deauthoriz|revoke)\\b'}, {'contract.has_state_var_matching': '(?i)(shares|shareBalance|shareBalances|totalShares|totalSupply|balances)'}, {'contract.has_function_matching': '(?i)^(deposit|mint|subscribe|claim|accrue|transfer|redeem|withdraw)$'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(deauthorize|removeFromWhitelist|revokeAccess|blacklist|unapprove|removeMember|remove)$'}, {'function.is_mutating': True}, {'function.has_param_of_type': 'address'}, {'function.has_param_name_matching': '(?i)^(account|user|member|investor|holder)$'}, {'function.writes_storage_matching': '(?i)(whitelist|allowlist|authorized|permitted|approved|members)'}, {'function.body_not_contains_regex': '(?i)(balanceOf\\s*\\(\\s*\\w+\\s*\\)|balances\\s*\\[\\s*\\w+\\s*\\]|shares\\s*\\[\\s*\\w+\\s*\\]|shareBalances\\s*\\[\\s*\\w+\\s*\\]|forceRedeem|forceExit|redeemFor|_burn\\s*\\(\\s*\\w+|seizeShares)'}, {'function.not_slither_synthetic': True}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r74-auth-deauthorized-keeps-shares: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
