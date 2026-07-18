"""
amm-pair-pre-creation-disables-hooks — generated from reference/patterns.dsl/amm-pair-pre-creation-disables-hooks.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py amm-pair-pre-creation-disables-hooks.yaml
Source: code4arena/slice_ac-GTE-Launchpad-M11
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AmmPairPreCreationDisablesHooks(AbstractDetector):
    ARGUMENT = "amm-pair-pre-creation-disables-hooks"
    HELP = "Launchpad registers swap / reward hooks only inside its own createPair flow. A third party who creates the same pair on the underlying DEX factory first squats the pair-address; the launchpad's hook never attaches and real traders bypass fees and rewards."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/amm-pair-pre-creation-disables-hooks.yaml"
    WIKI_TITLE = "Launchpad hook registration only on createPair — no migration path for pre-existing pair"
    WIKI_DESCRIPTION = "AMM launchpads often need to inject per-trade hooks (reward accrual, fee skim) at pair creation. If hook registration happens only inside `createPair` and not inside a separate `migrateHook` path, an attacker can call the underlying factory's `createPair` for the same `(token0, token1)` pair BEFORE the launchpad runs. The launchpad will then either revert (pair already exists) or — worse — associa"
    WIKI_EXPLOIT_SCENARIO = "GTE Launchpad M-11: attacker pre-creates the UniV3 pool at the canonical `(token0, 1, fee)` key before the launchpad runs. Launchpad's createPair path reverts on UniV3 but the launchpad records its own hook anyway against a sibling address, and trading routes through the pre-created pool with no hook — all launchpad fees and rewards are lost."
    WIKI_RECOMMENDATION = "Detect the pre-existing pair inside `createPair` (`if (factory.getPair(a,b) != address(0))`) and either register the hook against the existing pool or expose a permissioned `migrateHook(pair)` path that can attach the hook after the fact."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(Launchpad|Factory|createPair|pair\\[|getPair\\()'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(createPair|launch|deploy|initialize)'}, {'function.body_contains_regex': '(factory|Factory)\\.createPair|new\\s+LaunchpadPair|_register\\w*Hook|registerHook'}, {'function.body_not_contains_regex': 'if\\s*\\(\\s*\\w*pair\\s*!=\\s*address\\s*\\(\\s*0|already\\s*exists|migrateHook|_migrateHook|pairExists'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — amm-pair-pre-creation-disables-hooks: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
