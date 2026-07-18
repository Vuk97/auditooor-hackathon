"""
clone-only-gate-permits-shared-singleton-bricking — generated from reference/patterns.dsl/clone-only-gate-permits-shared-singleton-bricking.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py clone-only-gate-permits-shared-singleton-bricking.yaml
Source: auditooor-R111-base-azul-FN-6-narrowed-defense-in-depth
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CloneOnlyGatePermitsSharedSingletonBricking(AbstractDetector):
    ARGUMENT = "clone-only-gate-permits-shared-singleton-bricking"
    HELP = "Mining prompt only, not submission proof. Generic clone-family blast-radius smell: an externally-callable function whose ONLY access check is a clone-membership predicate (`isClone(msg.sender)` / `isFactoryOutput(msg.sender)` / `isProperGame(msg.sender)`) calls a destructive method on a shared singl"
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/clone-only-gate-permits-shared-singleton-bricking.yaml"
    WIKI_TITLE = "Clone-membership-only gate before destructive call on shared singleton (blast-radius smell)"
    WIKI_DESCRIPTION = "Mining prompt only, not submission proof. An externally-callable function gates its access ONLY on whether `msg.sender` is a member of a clone family (passes `isProperGame` / `isClone` / `isFactoryOutput`). After the gate, the function calls a destructive state-mutating method on a shared singleton (verifier, endpoint, comptroller — typically stored as `immutable`). The smell is the *asymmetry*: t"
    WIKI_EXPLOIT_SCENARIO = "Generic shape: a clone family `Foo` exposes `function actDestructive(...) external { if (!REGISTRY.isClone(msg.sender)) revert NotClone(); ... SHARED_SINGLETON.brick(); }`. SHARED_SINGLETON is `immutable` — every clone the factory produces shares the same instance. If clone creation is open (anyone can deploy a fresh clone via the factory, optionally posting a recoverable bond), the clone-only gat"
    WIKI_RECOMMENDATION = "Add a stronger access check ABOVE the clone-membership gate, so only a privileged role (guardian, owner, governance) can trigger destructive calls on shared infrastructure:\n\n```solidity\nfunction actDestructive(...) external {\n    if (msg.sender != GUARDIAN) revert NotGuardian();   // privileged "

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(Verifier|Game|Dispute|Aggregate|Clone|Endpoint|Bridge|Market|Pool|Pair|Spoke|Hub|cToken|Module)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '(!\\s*\\w+(?:\\s*\\(\\s*\\w+\\s*\\))?|require\\s*\\(\\s*\\w+(?:\\s*\\(\\s*\\w+\\s*\\))?)\\s*\\.\\s*(isGameProper|isProperGame|isGameRespected|isClone|isMember|isRegisteredGame|isRegistered|isValidClone|isAuthorizedClone|isKnownGame|isKnownClone|isFactoryOutput|isChild|isSpoke|isMarket)\\s*\\(\\s*msg\\.sender\\s*\\)'}, {'function.body_contains_regex': '\\b(I[A-Z]\\w+\\s*\\(\\s*[A-Z_][A-Z0-9_]*\\s*\\)|\\b[A-Z_][A-Z0-9_]*)\\.\\s*(nullify|disable|brick|freeze|halt|kill|terminate|pause|deactivate|permanentlyPause|burnDown)\\s*\\('}, {'function.body_not_contains_regex': '\\b(onlyOwner|onlyGuardian|onlyAdmin|onlyRole|hasRole)\\s*\\(|\\bmsg\\.sender\\s*(==|!=)\\s*(owner|guardian|admin|governance|timelock|GUARDIAN|OWNER|ADMIN|GOVERNANCE|TIMELOCK)\\b'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — clone-only-gate-permits-shared-singleton-bricking: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
