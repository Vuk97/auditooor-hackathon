"""
one-way-circuit-breaker-no-recovery-on-shared-singleton — generated from reference/patterns.dsl/one-way-circuit-breaker-no-recovery-on-shared-singleton.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py one-way-circuit-breaker-no-recovery-on-shared-singleton.yaml
Source: cross-engagement-base-azul-FN6-Verifier-nullified
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OneWayCircuitBreakerNoRecoveryOnSharedSingleton(AbstractDetector):
    ARGUMENT = "one-way-circuit-breaker-no-recovery-on-shared-singleton"
    HELP = "Shared-infrastructure contract (Verifier / Oracle / Registry / Hub / Factory) carries a one-way kill-switch flag set true by an external function with no reverse setter anywhere in the contract. Any caller that satisfies the gate can permanently brick the singleton for every downstream consumer."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/one-way-circuit-breaker-no-recovery-on-shared-singleton.yaml"
    WIKI_TITLE = "One-way circuit-breaker on shared singleton — clone-targeted brick risk"
    WIKI_DESCRIPTION = "An infrastructure contract intended to be shared by many consumers (clones reference it via immutable address, dependent vaults read its `paused()` view, downstream games invoke its `verify()`) defines a kill-switch flag — `nullified`, `disabled`, `frozen`, etc. — that an external entry-point flips to `true`, gating all subsequent calls via a `notNullified` / `whenNotDisabled` modifier. The contra"
    WIKI_EXPLOIT_SCENARIO = "An aggregate verifier stores TEE_VERIFIER and ZK_VERIFIER as immutable addresses; factory clones share both. The TEE verifier exposes `nullify()` callable by any proper/respected dispute game. An attacker creates a normal clone via the factory, supplies legal proof bytes that satisfy the clone-level nullification path, and the clone calls `TEE_VERIFIER.nullify()`. The shared verifier's `nullified "
    WIKI_RECOMMENDATION = "Add a guardian-gated reverse setter so the kill-switch is recoverable on false / malicious nullification:\n\n```solidity\naddress public immutable GUARDIAN;\n\nfunction unnullify() external {\n    if (msg.sender != GUARDIAN) revert NotGuardian();\n    nullified = false;\n    emit VerifierUnnullified"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(Verifier|Oracle|Registry|Hub|Factory|Singleton|Module|Manager|Validator)'}, {'contract.source_not_contains_regex': '\\bfunction\\s+(unnullify|undisable|unbrick|unfreeze|unhalt|unpause|reset|revive|reactivate|clearKill|reenable|enable)\\s*\\('}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '\\b(nullified|disabled|bricked|frozen|halted|permanentlyPaused|killed|terminated|deactivated)\\s*=\\s*true\\b'}, {'function.name_matches': '^(nullify|disable|brick|freeze|halt|kill|terminate|permanentlyPause|deactivate|burnDown|selfDestruct)$'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — one-way-circuit-breaker-no-recovery-on-shared-singleton: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
