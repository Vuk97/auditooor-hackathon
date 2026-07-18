"""
ioracle-queryexchangerate-returns-incorrect-blocktimems — generated from reference/patterns.dsl/ioracle-queryexchangerate-returns-incorrect-blocktimems.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ioracle-queryexchangerate-returns-incorrect-blocktimems.yaml
Source: code4arena audit 2024-11-nibiru
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class IoracleQueryexchangerateReturnsIncorrectBlocktimems(AbstractDetector):
    ARGUMENT = "ioracle-queryexchangerate-returns-incorrect-blocktimems"
    HELP = "`queryExchangeRate` returns `blockTimeMs` from live `block.timestamp` while sourcing `blockHeight` from a historical record."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ioracle-queryexchangerate-returns-incorrect-blocktimems.yaml"
    WIKI_TITLE = "IOracle.queryExchangeRate returns incorrect blockTimeMs"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: this row proves only the owned `queryExchangeRate` shape where historical `blockHeight` comes from a stored record but `blockTimeMs` is filled from live `block.timestamp * 1000`. NOT_SUBMIT_READY."
    WIKI_EXPLOIT_SCENARIO = "`queryExchangeRate` returns `blockTimeMs` from live `block.timestamp` while sourcing `blockHeight` from a historical record."
    WIKI_RECOMMENDATION = "Return `blockTimeMs` from the same historical exchange-rate record as `blockHeight`. Do not promote from this fixture smoke alone."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(queryExchangeRate|blockTimeMs|blockHeight)'}]
    _MATCH = [{'function.name_matches': '^queryExchangeRate$'}, {'function.body_contains_regex': '\\bblockTimeMs\\b'}, {'function.body_contains_regex': '\\bblockHeight\\b'}, {'function.body_contains_regex': '\\bblockHeight\\s*=\\s*[A-Za-z_][A-Za-z0-9_]*\\s*\\.\\s*blockHeight\\b'}, {'function.body_contains_regex': '\\bblockTimeMs\\s*=\\s*(?:block\\.timestamp\\s*\\*\\s*1000|1000\\s*\\*\\s*block\\.timestamp)\\b'}, {'function.body_not_contains_regex': '\\bblockTimeMs\\s*=\\s*[A-Za-z_][A-Za-z0-9_]*\\s*\\.\\s*blockTimeMs\\b'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" — ioracle-queryexchangerate-returns-incorrect-blocktimems: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
