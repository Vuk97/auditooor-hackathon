"""
r94-loop-oft-adapter-inventory-vs-source-supply-divergence-unchecked — generated from reference/patterns.dsl/r94-loop-oft-adapter-inventory-vs-source-supply-divergence-unchecked.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-oft-adapter-inventory-vs-source-supply-divergence-unchecked.yaml
Source: kelp-rseth-exploit-2026-04-18-banteg-postmortem
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopOftAdapterInventoryVsSourceSupplyDivergenceUnchecked(AbstractDetector):
    ARGUMENT = "r94-loop-oft-adapter-inventory-vs-source-supply-divergence-unchecked"
    HELP = "r94-loop-oft-adapter-inventory-vs-source-supply-divergence-unchecked"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-oft-adapter-inventory-vs-source-supply-divergence-unchecked.yaml"
    WIKI_TITLE = "r94-loop-oft-adapter-inventory-vs-source-supply-divergence-unchecked"
    WIKI_DESCRIPTION = "r94-loop-oft-adapter-inventory-vs-source-supply-divergence-unchecked"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-oft-adapter-inventory-vs-source-supply-divergence-unchecked"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = {'contract.source_matches_regex': '(OFT|Adapter|Bridge|LayerZero)', 'function.name_matches': '(?i)(lzReceive|_lzReceive|releaseFromInventory|creditTo|_creditTo|settleOftMessage)'}
    _MATCH = {'function.source_matches_regex': '(safeTransfer\\s*\\(|token\\.transfer\\s*\\(|underlying\\.transfer\\s*\\()', 'function.not_source_matches_regex': '(sourceLockedSupply|globalSupplyInvariant|sourceTotalSupplyQuery|lightClientRootMatches|verifySourceTotalLocked|crossChainSupplyReconciliation|assertSupplyInvariant|validateCrossChainAccounting)'}

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
                info = [f, f" — r94-loop-oft-adapter-inventory-vs-source-supply-divergence-unchecked: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
