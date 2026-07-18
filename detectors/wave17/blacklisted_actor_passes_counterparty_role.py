"""
blacklisted-actor-passes-counterparty-role — generated from reference/patterns.dsl/blacklisted-actor-passes-counterparty-role.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py blacklisted-actor-passes-counterparty-role.yaml
Source: auditooor-R75-code4rena-2024-07-munchables-29
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BlacklistedActorPassesCounterpartyRole(AbstractDetector):
    ARGUMENT = "blacklisted-actor-passes-counterparty-role"
    HELP = "stakeMunchable accepts a landlord address but never checks the landlord's blacklist status — blacklisted actor keeps earning tax."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/blacklisted-actor-passes-counterparty-role.yaml"
    WIKI_TITLE = "Counterparty address not blacklist-checked, letting banned actors earn passive tax"
    WIKI_DESCRIPTION = "`LandManager.stakeMunchable(landlord, tokenId, plotId)` enforces blacklist on the caller (`msg.sender`) but not on `landlord`. Every subsequent `_farmPlots` credits tax to the landlord. If `landlord` is on the MunchNFT blacklist, they should not receive rewards; but the blacklist is only checked on NFT transfers, not on cashflow. Blacklisted whales continue to accrue yield and can later transfer t"
    WIKI_EXPLOIT_SCENARIO = "Landlord L is blacklisted for fraud. L cannot transfer their NFT, but any user can still stake to L. Users continue to stake; L's unfedSchnibbles grows indefinitely. On unban (e.g. end of slashing period), L collects a large bag."
    WIKI_RECOMMENDATION = "In stakeMunchable, require `!MunchNFT.isBlocked(landlord) && !MunchNFT.isTokenBlocked(landlordsTokenId)`. Equivalently, short-circuit `_farmPlots` to skip crediting tax when landlord is currently blacklisted."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external'}, {'function.name_matches': '(?i)stakeTo|stakeWith|delegateTo|registerReferral|designateLandlord'}, {'function.body_contains_regex': '(?i)landlord|counterparty|referrer|delegate'}, {'function.body_not_contains_regex': '(?i)blacklist|isBlacklisted|_checkBlocked|_isBanned\\s*\\(\\s*landlord|_isBanned\\s*\\(\\s*counterparty'}, {'function.body_not_contains_regex': '(?i)MunchNFT\\(|NFT\\.isBlocked|blockedTokens'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — blacklisted-actor-passes-counterparty-role: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
