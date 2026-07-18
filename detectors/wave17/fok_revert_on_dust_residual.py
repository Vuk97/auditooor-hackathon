"""
fok-revert-on-dust-residual — generated from reference/patterns.dsl/fok-revert-on-dust-residual.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fok-revert-on-dust-residual.yaml
Source: code4arena/slice_ac-GTE-Spot-FOK
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FokRevertOnDustResidual(AbstractDetector):
    ARGUMENT = "fok-revert-on-dust-residual"
    HELP = "FOK order rejects any fill where residual > 0, rather than residual > lotSize. Orders that fill all but a sub-lot remainder incorrectly revert."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fok-revert-on-dust-residual.yaml"
    WIKI_TITLE = "FOK order rejects dust residual instead of rounding as filled"
    WIKI_DESCRIPTION = "Fill-Or-Kill semantics require the entire order to fill, but real-world matching produces a sub-lot-size residual due to price/lot discretization. Correct behavior: treat residual < lotSize as `fully filled`. When the engine reverts on residual > 0, legit FOK orders bounce off the book and the maker is denied execution."
    WIKI_EXPLOIT_SCENARIO = "Maker places FOK buy for 100.5 BTC on an ETH-BTC book with lotSize 0.01. Best ask is 100.49 BTC at 70k USD per BTC. Matching engine fills 100.49 and leaves 0.01 residual. Because the engine reverts on residual > 0 without checking against lotSize, the entire FOK reverts. Maker believes the market was uncrossable."
    WIKI_RECOMMENDATION = "Compare residual against lotSize (or the market's `MIN_FILL`): `if (residual < lotSize) treat as fully filled`. FOK should revert only when residual exceeds a meaningful unfilled threshold."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(FOK|fillOrKill|FillOrKill)|lotSize|LOT_SIZE'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '(fillOrder|matchOrder|_match|fill)'}, {'function.body_contains_regex': '(FOK|fillOrKill|isFOK)'}, {'function.body_contains_regex': 'residual\\s*>\\s*0|remaining\\s*!=\\s*0|filled\\s*!=\\s*order\\.(size|qty|amount)'}, {'function.body_not_contains_regex': 'residual\\s*>\\s*lotSize|residual\\s*>=\\s*LOT_SIZE|remaining\\s*>\\s*(MIN_LOT|lot|lotSize)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fok-revert-on-dust-residual: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
