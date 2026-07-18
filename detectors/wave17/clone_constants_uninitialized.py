"""
clone-constants-uninitialized — generated from reference/patterns.dsl/clone-constants-uninitialized.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py clone-constants-uninitialized.yaml
Source: solodit-novel/slice_af-Lido-Fixed-Income
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CloneConstantsUninitialized(AbstractDetector):
    ARGUMENT = "clone-constants-uninitialized"
    HELP = "Contract is deployed via Clones.clone(...) but critical state vars (rate/fee/decimals) are set via inline declaration, not inside initialize(); clones read zero and break division or fee accrual."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/clone-constants-uninitialized.yaml"
    WIKI_TITLE = "Clone proxy reads zero for inline-initialized state vars"
    WIKI_DESCRIPTION = "EIP-1167 minimal proxies copy only the implementation bytecode, not storage. When a contract intended to be cloned declares `uint256 public rate = 1e18;` inline, the master contract holds the constant but every clone reads `rate == 0`. Any divison `x / rate` reverts and any `amount * rate / PRECISION` returns 0."
    WIKI_EXPLOIT_SCENARIO = "Master contract declares `uint256 public exchangeRate = 1e18;` inline. `CloneFactory.create()` deploys a minimal proxy and calls `clone.initialize(asset)` which only sets `asset`. First user calls `deposit(100e18)`; internally `shares = amount * 1e18 / exchangeRate` panics with division-by-zero. Or worse, `fee = amount * feeBps / 10_000` silently becomes 0 because `feeBps` is also inline-initializ"
    WIKI_RECOMMENDATION = "Move every state-var initializer into `initialize()` (OpenZeppelin `Initializable` pattern). Declare state vars without default values, and set them inside the function that the factory calls after `Clones.clone(master)`."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'Clones\\.clone|cloneDeterministic|IClone|createClone|minimalProxy'}, {'contract.has_state_declaration_matching': '(uint256|uint128|address|bool)\\s+(public|internal|private)?\\s*\\w+\\s*=\\s*[^;]+'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_constructor': False}, {'function.name_matches': '^(initialize|__init|init)[A-Z_]?'}, {'function.body_not_contains_regex': 'rate\\s*=|fee\\s*=|precision\\s*=|decimals\\s*=|MAX_[A-Z_]+\\s*='}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — clone-constants-uninitialized: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
