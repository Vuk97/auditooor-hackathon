"""
fx-pendle-initializer-owner-order — generated from reference/patterns.dsl/fx-pendle-initializer-owner-order.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-pendle-initializer-owner-order.yaml
Source: github:pendle-finance/pendle-core-v2-public@3743c6a
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxPendleInitializerOwnerOrder(AbstractDetector):
    ARGUMENT = "fx-pendle-initializer-owner-order"
    HELP = "initialize() passes _owner directly to __BoringOwnableV2_init, but the intended pattern is to init with msg.sender (the deployer) and then transferOwnership to _owner. Passing _owner to __init makes the deployer-auth not hold, and the actual owner is set without going through the two-step transfer."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-pendle-initializer-owner-order.yaml"
    WIKI_TITLE = "Initializer passes intended owner directly to __init instead of msg.sender — ownership transfer bypass"
    WIKI_DESCRIPTION = "Initializer functions that accept an _owner parameter should call `__BoringOwnableV2_init(msg.sender)` (giving the deployer temporary ownership to configure the contract) and then `transferOwnership(_owner)`. Passing `_owner` directly to `__init` skips the msg.sender grant, potentially leaving the deployer (e.g., a factory) as permanent owner if transferOwnership is never called."
    WIKI_EXPLOIT_SCENARIO = "Pendle LimitRouter (2024): initialize(_feeRecipient, _owner) called __BoringOwnableV2_init(_owner) directly. The intended deployer (factory contract) never had ownership, so factory-only setup calls that need to happen post-deploy failed."
    WIKI_RECOMMENDATION = "Use the two-step pattern: `__BoringOwnableV2_init(msg.sender); ...; transferOwnership(_owner, true, false);`. This gives the deployer temporary authority to complete initialization before handing off to the intended owner."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '^initialize$'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^initialize$'}, {'function.body_contains_regex': '__BoringOwnableV2_init\\(|OwnableInit\\(|__Ownable_init\\('}, {'function.body_contains_regex': 'transferOwnership\\(_owner|transferOwnership\\(owner'}, {'function.body_contains_regex': '__BoringOwnableV2_init\\(_owner\\)|__Ownable_init\\(_owner\\)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fx-pendle-initializer-owner-order: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
