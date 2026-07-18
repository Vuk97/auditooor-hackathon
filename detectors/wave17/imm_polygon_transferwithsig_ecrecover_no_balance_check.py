"""
imm-polygon-transferwithsig-ecrecover-no-balance-check — generated from reference/patterns.dsl/imm-polygon-transferwithsig-ecrecover-no-balance-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py imm-polygon-transferwithsig-ecrecover-no-balance-check.yaml
Source: immunefi/polygon-mrc20-transferwithsig
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ImmPolygonTransferwithsigEcrecoverNoBalanceCheck(AbstractDetector):
    ARGUMENT = "imm-polygon-transferwithsig-ecrecover-no-balance-check"
    HELP = "Gasless transferWithSig / transferBySig recovers the signer via raw ecrecover but never checks the signer's balance nor rejects address(0). Malformed signatures recover to address(0); an unchecked _transfer debits the zero account and mints tokens to the attacker."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/imm-polygon-transferwithsig-ecrecover-no-balance-check.yaml"
    WIKI_TITLE = "transferWithSig mints from thin air via unchecked ecrecover + missing balance check (Polygon MRC20)"
    WIKI_DESCRIPTION = "Meta-tx ERC20 entrypoints such as `transferWithSig(bytes sig, uint256 amount, bytes32 tokenIdOrData, address to)` reconstruct a message digest, call `ecrecover(digest, v, r, s)` to obtain the spender, and then call an internal `_transfer(signer, to, amount)`. Two independent defects combine: (1) raw ecrecover returns `address(0)` for malformed inputs and is never compared against zero, and (2) `_t"
    WIKI_EXPLOIT_SCENARIO = "Polygon MRC20 (Dec 2021): attacker submits `transferWithSig(badSig, 9.3e9 * 1e18, ..., attacker)`. `ecrecover` returns `address(0)` because v/r/s are malformed. `_transferFrom(address(0), attacker, amount)` is called. `balances[address(0)]` is implicitly zero but the function does not check `balances[from] >= amount` before `balances[from] -= amount`; the storage slot is updated regardless. Attack"
    WIKI_RECOMMENDATION = "Three fixes, any one sufficient: (a) require the recovered signer is non-zero: `address signer = ecrecover(...); require(signer != address(0), \"bad sig\");`; (b) assert balance in `_transfer` even when called from meta-tx paths: `require(balances[from] >= amount);`; (c) replace raw ecrecover with O"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'balances\\s*\\[|_balances\\s*\\['}, {'contract.source_matches_regex': 'ecrecover\\s*\\('}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(transferWithSig|transferBySig|metaTransfer|permitTransfer|transferFromSig)$'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.body_contains_regex': 'ecrecover\\s*\\('}, {'function.body_not_contains_regex': 'balances\\s*\\[\\s*signer\\s*\\]\\s*>=|_balances\\s*\\[\\s*signer\\s*\\]\\s*>=|balanceOf\\s*\\(\\s*signer\\s*\\)\\s*>=|require\\s*\\(\\s*signer\\s*!=\\s*address\\s*\\(\\s*0|ECDSA\\.recover|SignatureChecker'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — imm-polygon-transferwithsig-ecrecover-no-balance-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
