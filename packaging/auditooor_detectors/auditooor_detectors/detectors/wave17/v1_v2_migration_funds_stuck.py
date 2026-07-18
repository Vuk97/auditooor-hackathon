"""
v1-v2-migration-funds-stuck — generated from reference/patterns.dsl/v1-v2-migration-funds-stuck.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py v1-v2-migration-funds-stuck.yaml
Source: solodit/C0015
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class V1V2MigrationFundsStuck(AbstractDetector):
    ARGUMENT = "v1-v2-migration-funds-stuck"
    HELP = "V1->V2 migration function burns/transfers old position and issues new receipt without first settling pending rewards or accrued yield — user ends the migration holding strictly less value than before."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/v1-v2-migration-funds-stuck.yaml"
    WIKI_TITLE = "V1->V2 migration forfeits unclaimed rewards / accrued yield"
    WIKI_DESCRIPTION = "Upgrade paths that move a user from a v1 receipt token to a v2 receipt token (bathTokenV1->bathTokenV2, old vault to new vault, L1 deposit to L2 deposit) must first settle every pending reward stream the v1 position was eligible for. When `migrate()` skips `accrue/harvest/updateRewards/claimRewards/syncYield` and jumps straight to `_burn(v1) ; _mint(v2)` or `safeTransfer` of the new share, any unc"
    WIKI_EXPLOIT_SCENARIO = "A user deposits in vault v1 and earns 100 tokens of pending reward under the v1 reward schedule, never calling `claim`. The v2 vault is deployed. The user calls `migrate(amount)`. The migrator burns their v1 shares and mints v2 shares 1:1. It never calls `accrueRewards(user)` or `claimRewards(user)` on the v1 side. The 100 pending rewards remain in the v1 contract's reward accounting tied to a now"
    WIKI_RECOMMENDATION = "Every migration entry point must first invoke the v1-side reward-settlement pathway (`accrue`, `harvest`, `claimRewards`, `updateRewards`, `syncYield`, whatever the protocol calls it) for the migrating user BEFORE the v1 balance is burned or transferred. Add an end-to-end test: user with non-zero `p"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'migrator|migration|migrated|v1|v2|oldVault|newVault'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'migrate|_migrate|migrateV1|migrateToV2|upgradePosition|convert|migrateDeposit'}, {'function.body_contains_regex': '\\.transfer|_burn|_mint|safeTransfer|_redeem'}, {'function.body_not_contains_regex': 'accrue|harvest|claimRewards|pendingReward|updateRewards|syncYield'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — v1-v2-migration-funds-stuck: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
