"""
fx-euler-erc4626-missing-vault-status-check — generated from reference/patterns.dsl/fx-euler-erc4626-missing-vault-status-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-euler-erc4626-missing-vault-status-check.yaml
Source: auditooor-R71-fixdiff-mined-euler-periphery-2b86f0c4
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxEulerErc4626MissingVaultStatusCheck(AbstractDetector):
    ARGUMENT = "fx-euler-erc4626-missing-vault-status-check"
    HELP = "ERC-4626 state-mutating entry point forwards to super without calling `evc.requireVaultStatusCheck()`; the vault status hook (cap enforcement, invariant checks) is never scheduled and caps are effectively unenforced."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-euler-erc4626-missing-vault-status-check.yaml"
    WIKI_TITLE = "ERC-4626 deposit/withdraw missing requireVaultStatusCheck — supply caps never verified"
    WIKI_DESCRIPTION = "EVC-aware vaults must call `evc.requireVaultStatusCheck()` at the end of any state-mutating entry point so the deferred checkVaultStatus hook (which enforces supply/borrow caps, pause invariants) is scheduled. Forgetting the call on a subset of entry points (typical on withdraw/redeem, or newly-added deposit variants) makes caps one-sided: deposits scheduled, withdraws silent. An attacker can use "
    WIKI_EXPLOIT_SCENARIO = "Euler ERC4626EVCCollateralCapped (2025-10): withdraw() forwarded to super.withdraw without requireVaultStatusCheck. A shaped deposit/withdraw sequence left the vault's internal supply-tracking stale relative to AmountCap, allowing total deposits to exceed the configured cap until the next cap-checking deposit came in."
    WIKI_RECOMMENDATION = "At the end of EVERY mutating public entry point (deposit, mint, withdraw, redeem, transfer, transferFrom, liquidate): call `evc.requireVaultStatusCheck()`. Add a CI check enumerating mutating externals and verifying each contains the call."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.inherits_any': ['ERC4626EVC', 'ERC4626', 'EVCUtil']}, {'contract.has_state_var_matching': 'supplyCap|depositCap|maxAmount|AmountCap'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(deposit|mint|withdraw|redeem)$'}, {'function.body_contains_regex': 'super\\.(deposit|mint|withdraw|redeem)'}, {'function.body_not_contains_regex': 'requireVaultStatusCheck|evc\\.requireVaultStatus'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fx-euler-erc4626-missing-vault-status-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
