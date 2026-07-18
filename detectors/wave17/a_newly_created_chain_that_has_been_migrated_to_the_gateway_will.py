"""
a-newly-created-chain-that-has-been-migrated-to-the-gateway-will — generated from reference/patterns.dsl/a-newly-created-chain-that-has-been-migrated-to-the-gateway-will.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-newly-created-chain-that-has-been-migrated-to-the-gateway-will.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ANewlyCreatedChainThatHasBeenMigratedToTheGatewayWill(AbstractDetector):
    ARGUMENT = "a-newly-created-chain-that-has-been-migrated-to-the-gateway-will"
    HELP = "A newly created chain that has been migrated to the gateway will be lost if tries to migrate back to L1"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-newly-created-chain-that-has-been-migrated-to-the-gateway-will.yaml"
    WIKI_TITLE = "A newly created chain that has been migrated to the gateway will be lost if tries to migrate back to L1"
    WIKI_DESCRIPTION = "## Summary\nA newly created chain that has been migrated to the gateway will be lost if tries to migrate back to L1\n\n## Vulnerability Details\n\nWhen a new chain is created, the `priorityTree` is initialized:\n\n```Solidity\ncontract DiamondInit is ZKChainBase, IDiamondInit {\n    using PriorityQueue for P"
    WIKI_EXPLOIT_SCENARIO = "A newly created chain that has been migrated to the gateway will be lost if tries to migrate back to L1"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches': '.*(priorityTree|startIndex|historicalRoots|forwardedBridgeBurn).*'}, {'function.reads_state_var_matching': '.*(forwardedBridgeBurn|historicalRoots|priorityTree).*'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.does_not_call_matching': '.*(accrue|update|sync|validate|check|refresh).*'}]

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
                info = [f, f" — a-newly-created-chain-that-has-been-migrated-to-the-gateway-will: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
