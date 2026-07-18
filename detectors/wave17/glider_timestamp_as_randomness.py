"""
glider-timestamp-as-randomness — generated from reference/patterns.dsl/glider-timestamp-as-randomness.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-timestamp-as-randomness.yaml
Source: glider/timestamp-as-randomness
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderTimestampAsRandomness(AbstractDetector):
    ARGUMENT = "glider-timestamp-as-randomness"
    HELP = "Pseudo-random number derived from `keccak256(block.timestamp/prevrandao/number)` reduced by `%` to a small range. Miner/validator can manipulate the inputs (within grind/skip limits); the result is adversary-predictable."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-timestamp-as-randomness.yaml"
    WIKI_TITLE = "Weak randomness from block.timestamp / prevrandao hash"
    WIKI_DESCRIPTION = "Using `keccak256(abi.encode(block.timestamp, block.number))` (or prevrandao) as entropy for raffles, lotteries, or loot boxes is adversary-predictable. Post-merge `prevrandao` improves on `difficulty` but validators can still grind by skipping blocks, especially for low-range outcomes."
    WIKI_EXPLOIT_SCENARIO = "NFT mint has 1% chance of 'rare' trait based on `keccak256(abi.encode(block.timestamp, minter)) % 100 == 0`. Validator sees their own pending mint tx, can delay block inclusion a few slots to find a block where the hash lands on 0."
    WIKI_RECOMMENDATION = "Use Chainlink VRF (or Pyth Entropy) for on-chain randomness. For low-value use cases, commit-reveal with a commit block at least 128 blocks in the past mitigates grind by a single actor."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.computes_keccak': True}, {'function.body_contains_regex': '(?is)keccak256\\s*\\([^;{}]*block\\.(timestamp|prevrandao|difficulty|number)[^;{}]*\\)\\s*\\)*\\s*%'}, {'function.body_not_contains_regex': 'VRF|ChainlinkVRF|requestRandomness|randao'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-timestamp-as-randomness: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
