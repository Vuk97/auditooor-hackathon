"""
glider-reward-mint-on-repeat-poke — generated from reference/patterns.dsl/glider-reward-mint-on-repeat-poke.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-reward-mint-on-repeat-poke.yaml
Source: hexens-glider/unlimited-reward-mint-via-repeated-pokeaccrue-with
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderRewardMintOnRepeatPoke(AbstractDetector):
    ARGUMENT = "glider-reward-mint-on-repeat-poke"
    HELP = "Public accrue/poke/harvest function mints reward tokens without tracking the last-accrual timestamp. Calling it multiple times per block mints rewards multiple times, inflating supply."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-reward-mint-on-repeat-poke.yaml"
    WIKI_TITLE = "Reward poke mints per call — no last-accrual stamp"
    WIKI_DESCRIPTION = "Reward distributor exposes poke()/accrue() that computes rewards from (rewardPerSecond * elapsed). If elapsed is computed from block.timestamp - lastUpdate and lastUpdate is never written, or if it is written after the mint but the mint amount doesn't depend on elapsed, the same tranche can be minted repeatedly in a single block."
    WIKI_EXPLOIT_SCENARIO = "poke() mints rewardPerBlock to the caller and updates lastBlock AFTER the mint. Attacker calls poke() in a tight loop inside one transaction; each call mints a full block's worth because lastBlock is still the previous block until after the first mint."
    WIKI_RECOMMENDATION = "Gate all reward mints on a monotonically increasing lastUpdate timestamp/block written BEFORE the mint. Compute amount as (now - last) * rate and update last = now atomically."

    _PRECONDITIONS = [{'contract.source_matches_regex': '\\baccrue\\b|\\bpoke\\b|\\bharvest\\b|\\bupdate(Reward|Index)\\b'}]
    _MATCH = [{'function.name_matches': '^(poke|accrue|updateReward|updateRewards|updateIndex|updateRewardIndex|updateAccrual|updateDistribution|updatePool|updateYield|harvest|harvestRewards|distribute|distributeRewards|claim|claimRewards|pokeAccrue|_poke|_accrue|_updateReward|_updateIndex)$'}, {'function.kind': 'external_or_public'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.body_contains_regex': '\\.mint\\s*\\(|totalSupply\\s*\\+='}, {'function.body_not_contains_regex': 'lastAccrue|lastUpdate|lastMint|block\\.(timestamp|number)\\s*[-<>=]'}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-reward-mint-on-repeat-poke: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
