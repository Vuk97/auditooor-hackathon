"""
glider-blockhash-usage-that-can-lead-to-a-staleness — generated from reference/patterns.dsl/glider-blockhash-usage-that-can-lead-to-a-staleness.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-blockhash-usage-that-can-lead-to-a-staleness.yaml
Source: hexens-glider/blockhash-usage-that-can-lead-to-a-staleness
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderBlockhashUsageThatCanLeadToAStaleness(AbstractDetector):
    ARGUMENT = "glider-blockhash-usage-that-can-lead-to-a-staleness"
    HELP = "Blockhash Staleness Vulnerability"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-blockhash-usage-that-can-lead-to-a-staleness.yaml"
    WIKI_TITLE = "Blockhash Staleness Vulnerability"
    WIKI_DESCRIPTION = "Detects potential blockhash staleness issues where blockhash() might return 0 due to EVM limitations. The EVM only stores the last 256 block hashes. If blockhash() is called for a block older than 256 blocks, it returns 0. Vulnerable patterns: 1. blockhash(storedBlockNumber) where storedBlockNumber might be stale 2. No check for block.number - storedBlockNumber > 255 3. Fallback to predictable alt"
    WIKI_EXPLOIT_SCENARIO = "Transpiled from Hexens Glider query blockhash-usage-that-can-lead-to-a-staleness. Tags: blockhash, staleness, randomness, evm, nft."
    WIKI_RECOMMENDATION = "Apply the check implied by the original Glider query — see hexens-glider source for context."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.calls_function_matching': '^(blockhash)$'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-blockhash-usage-that-can-lead-to-a-staleness: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
