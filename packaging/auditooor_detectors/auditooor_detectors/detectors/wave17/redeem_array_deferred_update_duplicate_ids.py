"""
redeem-array-deferred-update-duplicate-ids — generated from reference/patterns.dsl/redeem-array-deferred-update-duplicate-ids.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py redeem-array-deferred-update-duplicate-ids.yaml
Source: defimon-2026-04-15-lootbot-9.6k
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RedeemArrayDeferredUpdateDuplicateIds(AbstractDetector):
    ARGUMENT = "redeem-array-deferred-update-duplicate-ids"
    HELP = "redeem(uint256[] ids) accumulates per-id reward by reading nextRedeem[ids[i]] in a loop, but writes nextRedeem[ids[i]] AFTER the loop (or in a tail-flush). Duplicate IDs in the array each see the same un-updated cooldown and accumulate N× the reward."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/redeem-array-deferred-update-duplicate-ids.yaml"
    WIKI_TITLE = "redeem(uint256[] ids) loop reads per-id cooldown but writes after loop, allowing duplicate-id over-claim"
    WIKI_DESCRIPTION = "Staking / NFT-rewards contracts with a per-id `nextRedeem[id]` (or `lastClaim[id]` / `cooldown[id]`) mapping iterate a caller-supplied id array, calling `_redeemable(id)` per entry to compute claimable reward. When the mapping write is deferred (post-loop, batched, or wrapped in a helper called outside the loop), each duplicate entry re-reads the SAME stale cooldown and adds another full reward. T"
    WIKI_EXPLOIT_SCENARIO = "LootBot.xyz (Apr 15 2026, ~$9.6K stolen, tx 0xab19752a450a205ccaca9afb8505e2d8b79593ee2edab1f67bdec27a4f14871f). Attacker held one xLoot NFT (id 155) eligible to redeem ~$60 in rewards. They called `redeem([155, 155, 155, ..., 155])` with the same id 155 times. The body loop read `_redeemable(155)` per iteration — each time seeing the SAME `nextRedeem[155]` (which the contract only updated AFTER t"
    WIKI_RECOMMENDATION = "Move the per-id state update INSIDE the per-iteration body, BEFORE the transfer: `nextRedeem[ids[i]] = block.timestamp + cooldownPeriod;`. Or assert array uniqueness: at the top of the function build a `seen` set. Or require strictly-increasing input: `for (uint i=1; i<ids.length; ++i) require(ids[i"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)mapping\\s*\\(\\s*uint\\d*\\s*=>\\s*uint\\d*\\s*\\)\\s*(public|internal|private)?\\s*(nextRedeem|lastRedeem|nextClaim|lastClaim|nextHarvest|cooldown|redeemAt|claimAt)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(redeem|redeemAll|redeemMultiple|claim|claimAll|harvest|compound|sell)([A-Z_].*)?$'}, {'function.has_param_of_type': 'uint256[]'}, {'function.body_contains_regex': '(?i)\\b_?(redeemable|claimable|reward|earned|owed)\\s*\\(\\s*\\w+\\s*\\[\\s*\\w+\\s*\\]\\s*\\)'}, {'function.body_contains_regex': '(?i)\\}\\s*for\\s*\\(\\s*uint\\d*\\s+\\w+\\s*=\\s*0\\s*;\\s*\\w+\\s*<\\s*\\w+\\.length'}, {'function.body_contains_regex': '(?i)(nextRedeem|lastRedeem|nextClaim|lastClaim|nextHarvest|redeemAt|claimAt)\\s*\\[\\s*\\w+\\s*\\[\\s*\\w+\\s*\\]\\s*\\]\\s*='}, {'function.body_not_contains_regex': '(?i)EnumerableSet|seenIds\\s*\\[|require\\s*\\(\\s*!\\s*seen|require\\s*\\(\\s*ids\\[i\\]\\s*>\\s*ids\\[i-1\\]|require\\s*\\(\\s*ids\\[i\\]\\s*!=\\s*ids\\[i-1\\]'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — redeem-array-deferred-update-duplicate-ids: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
