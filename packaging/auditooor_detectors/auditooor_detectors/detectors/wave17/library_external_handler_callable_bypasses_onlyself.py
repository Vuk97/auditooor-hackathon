"""
library-external-handler-callable-bypasses-onlyself — generated from reference/patterns.dsl/library-external-handler-callable-bypasses-onlyself.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py library-external-handler-callable-bypasses-onlyself.yaml
Source: snowbridge-r109-source-mine-handlersv2-handlersv1
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LibraryExternalHandlerCallableBypassesOnlyself(AbstractDetector):
    ARGUMENT = "library-external-handler-callable-bypasses-onlyself"
    HELP = "A Solidity `library` exposes `external` (not `internal`) handler functions and relies on a CALLER's `onlySelf` modifier for access control. The library's external functions are deployed to a discoverable address and callable directly, bypassing the dispatcher's gate."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/library-external-handler-callable-bypasses-onlyself.yaml"
    WIKI_TITLE = "Library external function used as authorized handler is callable directly"
    WIKI_DESCRIPTION = "Solidity libraries with `internal` functions are inlined into the caller's bytecode at compile time. Libraries with `external` functions, however, are deployed as a separate contract at link time, and callers invoke them via DELEGATECALL or, depending on the call site, plain CALL. When a project structures inbound-message handlers as `library X { function handlerA(...) external { ... } }` and gate"
    WIKI_EXPLOIT_SCENARIO = "Snowbridge `HandlersV2.upgrade(bytes calldata data)` is declared `external`. The function is intended to be reachable only via the Gateway `v2_dispatchCommand` flow, which is `onlySelf`-gated. But HandlersV2 is deployed to a discoverable address (e.g., 0xH...). An attacker calls HandlersV2.upgrade(maliciousData) directly. Inside the function: `Upgrade.upgrade(params.impl, params.implCodeHash, para"
    WIKI_RECOMMENDATION = "Convert all `library X { function foo(...) external; }` handler functions to `internal` so they are inlined into the dispatcher and have no separately-deployed address. If the dispatcher must remain a thin trampoline (e.g., to keep the proxy small), use a regular contract with the handlers as `inter"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'library\\s+\\w+\\s*\\{[\\s\\S]*?function\\s+\\w+\\s*\\([^)]*\\)\\s+external'}]
    _MATCH = [{'function.kind': 'external'}, {'function.body_contains_regex': '\\.transferFrom\\s*\\(|\\.mint\\s*\\(|\\.burn\\s*\\(|CoreStorage\\.layout\\(\\)|AssetsStorage\\.layout\\(\\)|\\$\\.\\w+\\s*='}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*msg\\.sender\\s*==|onlyGateway|onlySelf|onlyAuthorized'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — library-external-handler-callable-bypasses-onlyself: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
