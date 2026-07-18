"""
block-number-time-assumption — generated from reference/patterns.dsl/block-number-time-assumption.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py block-number-time-assumption.yaml
Source: auditooor
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BlockNumberTimeAssumption(AbstractDetector):
    ARGUMENT = "block-number-time-assumption"
    HELP = "Contract converts `block.number` to seconds using a hard-coded 12/13/15-second multiplier (or a `blocksPerDay` literal) that holds only on Ethereum mainnet. On Arbitrum (~0.25s), Optimism / Base / Polygon (~2s), BSC (~3s) the derived duration is wrong by an integer multiple — emissions, vesting, and"
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/block-number-time-assumption.yaml"
    WIKI_TITLE = "Block-number-to-time conversion assumes Ethereum mainnet block time"
    WIKI_DESCRIPTION = "A common portability bug: code originally deployed on Ethereum mainnet computes elapsed seconds as `block.number * 12` (or a related literal). When the same contract is redeployed on an L2 or alt-L1 where block production is faster or slower, the derived `seconds` value no longer matches wall-clock time. Vesting schedules release too fast or too slow, reward emissions inflate or starve, auction ti"
    WIKI_EXPLOIT_SCENARIO = "Staking contract emits rewards at `rewardPerBlock * (block.number - startBlock)` deployed to Arbitrum Nova (0.25s blocks). The author intended `rewardPerSecond`-equivalent emission derived from Ethereum's 12s blocks. Actual emission rate is 48x higher than intended. Within hours, reward reserves are drained and legitimate stakers receive no rewards. Symmetric failure mode on chains with slower blo"
    WIKI_RECOMMENDATION = "Use `block.timestamp` for any wall-clock measurement (vesting, unlocks, deadlines, rate accrual). Reserve `block.number` strictly for ordering, snapshot checkpointing, or cases where you want chain-agnostic block-height semantics. If cross-chain portability is required, make the blocks-per-second co"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': {'regex': 'block\\.number\\s*\\*\\s*(12|13|15)\\b|\\(\\s*block\\.number\\s*[-+]\\s*[^)]+\\)\\s*\\*\\s*(12|13|15)\\b|blocksPerDay\\s*=\\s*\\d+'}}, {'function.body_not_contains_regex': 'block\\.timestamp'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — block-number-time-assumption: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
