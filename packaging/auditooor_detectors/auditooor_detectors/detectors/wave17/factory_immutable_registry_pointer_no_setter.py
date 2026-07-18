"""
factory-immutable-registry-pointer-no-setter — generated from reference/patterns.dsl/factory-immutable-registry-pointer-no-setter.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py factory-immutable-registry-pointer-no-setter.yaml
Source: lisa-mine-r99-case-03456-tally-safeguard-2022
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FactoryImmutableRegistryPointerNoSetter(AbstractDetector):
    ARGUMENT = "factory-immutable-registry-pointer-no-setter"
    HELP = "Factory contract assigns a `registry` / `directory` / `catalog` pointer in its constructor without exposing a privileged `setRegistry()` setter. If the registry must ever be redeployed (governance migration, bug-fix, or change of ownership semantics), the entire factory must be redeployed too — and "
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/factory-immutable-registry-pointer-no-setter.yaml"
    WIKI_TITLE = "Factory holds an immutable registry pointer with no setter"
    WIKI_DESCRIPTION = "A factory contract that records its child deployments into an external Registry must allow the registry pointer itself to be updated. When the factory's constructor performs `registry = registry_;` and provides no `setRegistry`-style setter (gated by the appropriate role), there is no upgrade path: a new registry forces a new factory, which forces every caller pinned to the old factory address to "
    WIKI_EXPLOIT_SCENARIO = "Governance discovers a permission-model bug in the Registry (e.g. anyone can call `register()`, allowing front-running of CREATE addresses to grief the factory). The fix requires deploying a new Registry. Because Factory has no setRegistry, governance must redeploy the factory. Any external system that hard-coded the factory address (subgraph indexers, allow-lists, integrators) breaks until the ne"
    WIKI_RECOMMENDATION = "Expose a setter `setRegistry(address)` gated by `onlyOwner` / `onlyAdmin` / a timelock'd governance role. Emit an event on update so off-chain consumers can re-index. Even if the registry is intended to be permanent, a setter behind a timelock is the safer null-op, since it preserves an upgrade path"

    _PRECONDITIONS = [{'contract.has_function_matching': 'create|deploy|build|new[A-Z]'}, {'contract.has_state_var_matching': '^(registry|directory|catalog|registryAddress)$'}, {'contract.has_function_body_matching': '\\b(registry|directory|catalog)\\s*=\\s*[a-zA-Z_][a-zA-Z0-9_]*\\s*;'}, {'contract.has_no_function_body_matching': 'function\\s+(setRegistry|updateRegistry|changeRegistry|setDirectory|updateDirectory|setCatalog)\\b'}]
    _MATCH = [{'function.kind': 'any'}, {'function.is_constructor': True}, {'function.body_contains_regex': '\\b(registry|directory|catalog)\\s*=\\s*[a-zA-Z_][a-zA-Z0-9_]*\\s*;'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — factory-immutable-registry-pointer-no-setter: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
