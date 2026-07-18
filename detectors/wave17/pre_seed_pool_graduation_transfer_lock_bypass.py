"""
pre-seed-pool-graduation-transfer-lock-bypass — generated from reference/patterns.dsl/pre-seed-pool-graduation-transfer-lock-bypass.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py pre-seed-pool-graduation-transfer-lock-bypass.yaml
Source: solodit-novel/slice_ae
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PreSeedPoolGraduationTransferLockBypass(AbstractDetector):
    ARGUMENT = "pre-seed-pool-graduation-transfer-lock-bypass"
    HELP = "Transfer lock exempts the target Uniswap pair address but does not gate that exemption on the graduation flag. Any matching address accepts transfers pre-launch."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/pre-seed-pool-graduation-transfer-lock-bypass.yaml"
    WIKI_TITLE = "Pre-seed transfer lock exempts pool before graduation"
    WIKI_DESCRIPTION = "Launch tokens often restrict transfers until a graduation event (liquidity migration, TGE). The common fix allows transfers to the canonical pool address. But if that exemption is always on, transfers to the pool address go through even before graduation — if an attacker can force-create a pool (e.g., via factory front-run) or if the address is predictable, they can side-channel liquidity out of t"
    WIKI_EXPLOIT_SCENARIO = "Memecoin enables _transfer exemption for `pair = IUniswapV2Factory(factory).getPair(token, weth)`. Attacker front-runs graduation to create the pair themselves, then transfers locked tokens into the pair, bypassing the lock entirely. Pre-seed-Uniswap-Pool-Graduation finding."
    WIKI_RECOMMENDATION = "Only allow the pool exemption after the graduation flag flips: `require(graduated || recipient != pair)`. Prevent pool creation until graduation by deploying the pair atomically inside the graduation function."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'graduation|launch|preSeed|locked|transferLock|pair\\b|IUniswapV2Pair|IUniswapV3Pool'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': '^(transfer|_transfer|_update)$'}, {'function.body_contains_regex': 'pair|pool|IUniswapV2Pair|IUniswapV3Pool|graduat'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*graduated|require\\s*\\(\\s*launch(ed|Time)\\s*<|require\\s*\\(\\s*block\\.timestamp\\s*>=?\\s*launchTime|hasGraduated'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — pre-seed-pool-graduation-transfer-lock-bypass: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
