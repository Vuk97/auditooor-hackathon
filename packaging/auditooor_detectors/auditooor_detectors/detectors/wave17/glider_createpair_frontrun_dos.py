"""
glider-createpair-frontrun-dos — generated from reference/patterns.dsl/glider-createpair-frontrun-dos.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-createpair-frontrun-dos.yaml
Source: hexens-glider/create-pair-do-s
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderCreatepairFrontrunDos(AbstractDetector):
    ARGUMENT = "glider-createpair-frontrun-dos"
    HELP = "Function calls `factory.createPair(a,b)` without first checking `getPair(a,b)`. Attacker frontruns the deploy by pre-creating the pair, making `createPair` revert, and permanently DoS-ing the victim's launch path."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-createpair-frontrun-dos.yaml"
    WIKI_TITLE = "createPair called without getPair precheck (frontrun DoS)"
    WIKI_DESCRIPTION = "Uniswap-V2-style factories revert in `createPair` when the pair already exists. A launcher/launchpad contract that unconditionally calls `createPair` in its deploy flow is DoSable — an attacker merely sends a tx creating the same pair one block earlier, permanently bricking the launcher for that token."
    WIKI_EXPLOIT_SCENARIO = "LaunchpadFactory.createToken() deploys ERC20 and calls `v2Factory.createPair(token, weth)`. Attacker monitors the mempool, calls `v2Factory.createPair(expectedToken, weth)` with higher gas. Original tx reverts in createPair. The launcher has no retry path that accepts an existing pair → token launch is permanently stuck."
    WIKI_RECOMMENDATION = "Check first: `address pair = factory.getPair(a,b); if (pair == address(0)) pair = factory.createPair(a,b);`. Alternative: wrap in try/catch and fall through to the existing pair on revert."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'createPair|IUniswapV2Factory|IFactory'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': '\\.createPair\\s*\\('}, {'function.body_not_contains_regex': 'getPair\\s*\\(|pairFor\\s*\\(|try\\s+\\w*[Ff]actory\\s*\\.\\s*createPair|try\\s+\\w+\\s*\\.\\s*createPair|existingPair\\s*!='}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-createpair-frontrun-dos: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
