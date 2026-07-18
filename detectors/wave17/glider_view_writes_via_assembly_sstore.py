"""
glider-view-writes-via-assembly-sstore — generated from reference/patterns.dsl/glider-view-writes-via-assembly-sstore.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-view-writes-via-assembly-sstore.yaml
Source: glider/view-assembly-sstore
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderViewWritesViaAssemblySstore(AbstractDetector):
    ARGUMENT = "glider-view-writes-via-assembly-sstore"
    HELP = "Function declared `view` contains an assembly block that executes `sstore`. The Solidity `view` annotation is bypassed — the function actually mutates storage, misleading integrators and downstream static analyzers."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-view-writes-via-assembly-sstore.yaml"
    WIKI_TITLE = "`view` function writes storage via inline assembly `sstore`"
    WIKI_DESCRIPTION = "`view` is a compiler hint, not a runtime guarantee. Assembly blocks can emit `SSTORE` regardless. Integrators (wallets, price oracles, Chainlink feeds) often assume `view` is side-effect-free and call it in simulation paths; hidden sstore can poison adjacent state or bypass reentrancy guards."
    WIKI_EXPLOIT_SCENARIO = "Price oracle helper advertised as `getPrice() external view` runs `assembly { sstore(slot, newPrice) }` to cache recent observations. Chainlink adapter simulates the call and unintentionally mutates oracle state (e.g. twap accumulator), skewing the next tick."
    WIKI_RECOMMENDATION = "Never write storage in a `view` function. If caching is needed, mark the function `external` without `view` and expose an explicit `peek()` view for read-only consumers."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.state_mutability': 'view'}, {'function.assembly_block_matches': 'sstore\\s*\\('}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" — glider-view-writes-via-assembly-sstore: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
