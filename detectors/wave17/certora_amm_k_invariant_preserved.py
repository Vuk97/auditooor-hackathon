"""
certora-amm-k-invariant-preserved — generated from reference/patterns.dsl/certora-amm-k-invariant-preserved.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py certora-amm-k-invariant-preserved.yaml
Source: certora-examples/AMM/kInvariantPreserved
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CertoraAmmKInvariantPreserved(AbstractDetector):
    ARGUMENT = "certora-amm-k-invariant-preserved"
    HELP = "AMM reserves are mutated without re-asserting `reserve0 * reserve1 >= oldReserve0 * oldReserve1` — Certora `kInvariantPreserved` invariant violated."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/certora-amm-k-invariant-preserved.yaml"
    WIKI_TITLE = "AMM reserves mutated without k-invariant re-check"
    WIKI_DESCRIPTION = "Certora's AMM spec (mirroring Uniswap's `require(balance0Adjusted * balance1Adjusted >= reserve0 * reserve1 * 1000**2, 'K')`) proves that every swap preserves or grows `reserve0 * reserve1` (fees grow it). A swap variant / admin rebalance that writes reserves without the K check lets a user extract value: they send in tokenIn, the path does the math with stale reserves or a wrong fee, writes new r"
    WIKI_EXPLOIT_SCENARIO = "A governance-gated `rescueMisplaced(to, amount0, amount1)` is added to a Uniswap-fork pair. It transfers out amount0 and amount1, then writes `_reserve0 -= amount0; _reserve1 -= amount1;` — proportional on the surface, but the K check is missing. If the rescue isn't exactly proportional to the current reserve ratio, K drops. Subsequent LPs withdraw against the lowered reserves and realize less tha"
    WIKI_RECOMMENDATION = "Every path that writes reserves must end with `require(balance0 * balance1 >= oldReserve0 * oldReserve1, 'K')`. Never expose a bare reserve setter. Prove Certora's `kInvariantPreserved` on every reserves-touching function."

    _PRECONDITIONS = [{'contract.has_state_var_matching': '(?i)(reserve0|reserve1|_reserve0|_reserve1|reserves|reserveA|reserveB)'}, {'contract.source_matches_regex': '(?i)(swap|uniswap|amm|pair|pool|xyk|constantProduct)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': '(?i)^(swap|_swap|rebalance|skim|sync|rescue|updateReserves|setReserves|emergency)[A-Za-z0-9_]*'}, {'function.writes_storage_matching': '(?i)(reserve0|reserve1|_reserve0|_reserve1|reserves|reserveA|reserveB)'}, {'function.body_not_contains_regex': '(?i)(reserve0\\s*\\*\\s*reserve1|reserveA\\s*\\*\\s*reserveB|balance0Adjusted\\s*\\*\\s*balance1Adjusted|require[^;]*K|require[^;]*invariant|\\*\\s*10\\*\\*|\\*\\s*1e|k\\s*<=|k\\s*>=)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — certora-amm-k-invariant-preserved: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
