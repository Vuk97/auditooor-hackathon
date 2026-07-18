"""
rebasing-token-allowance-drift-in-router — generated from reference/patterns.dsl/rebasing-token-allowance-drift-in-router.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py rebasing-token-allowance-drift-in-router.yaml
Source: auditooor-R75-code4rena-2024-06-thorchain-85

Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY.
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RebasingTokenAllowanceDriftInRouter(AbstractDetector):
    ARGUMENT = "rebasing-token-allowance-drift-in-router"
    HELP = "Per-vault allowance is tracked in raw units and arithmetic assumes 1:1 with balance — rebasing tokens break this invariant, enabling cross-vault theft."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/rebasing-token-allowance-drift-in-router.yaml"
    WIKI_TITLE = "Per-vault allowance tracking breaks under rebasing tokens, enabling cross-vault theft"
    WIKI_DESCRIPTION = "The router stores `_vaultAllowance[vault][asset]` equal to the raw units the vault is entitled to move. Solidity math assumes raw balance and allowance scale together. For a rebasing token like AMPL, a positive rebase halves the contract's balance (in units) while leaving stored allowances unchanged. A malicious vault who deposited pre-rebase and set its own address as recipient now has `allowance"
    WIKI_EXPLOIT_SCENARIO = "Attacker deposits 1000 AMPL pre-rebase (allowance = 1000). Rebase halves supply: contract balance = 500, allowance still 1000. Legit user deposits 1000 AMPL post-rebase → balance = 1500, allowance[attacker] = 1000 still satisfiable. Attacker calls transferAllowance to a malicious router, pulls 1000 AMPL. Legit user's withdrawable dropped from 1000 to 500."
    WIKI_RECOMMENDATION = "Maintain allowances in rebasing-invariant units (e.g., `gons` for AMPL). Alternatively, whitelist only non-rebasing tokens and explicitly block known rebasers. On every deposit/withdraw, also refresh `_vaultAllowance` to min(stored, actual balanceOf)."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(_vaultAllowance|rebasing|AMPL|stETH|safeTransferFrom)'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.name_matches': '(?i)transferAllowance|_routerDeposit|_approveOnVault|deposit\\w*'}, {'function.body_contains_regex': '(?i)_vaultAllowance\\s*\\[[^\\]]+\\]\\s*\\[[^\\]]+\\]\\s*(-=|=)'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.body_contains_regex': '(?i)safeTransferFrom|\\.transferFrom\\(|\\.approve\\('}, {'function.body_not_contains_regex': '(?i)balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\)|_gonsPerFragment|supportsRebasing|NoRebase'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — rebasing-token-allowance-drift-in-router: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
