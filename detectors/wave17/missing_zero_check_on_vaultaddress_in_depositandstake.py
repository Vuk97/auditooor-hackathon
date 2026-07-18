"""
missing-zero-check-on-vaultaddress-in-depositandstake — generated from reference/patterns.dsl/missing-zero-check-on-vaultaddress-in-depositandstake.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py missing-zero-check-on-vaultaddress-in-depositandstake.yaml
Source: zellic audit Steer - Zellic Audit Report
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MissingZeroCheckOnVaultaddressInDepositandstake(AbstractDetector):
    ARGUMENT = "missing-zero-check-on-vaultaddress-in-depositandstake"
    HELP = "depositAndStake compares getPool(poolId).stakingToken to vaultAddress without a visible vaultAddress zero-address guard."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/missing-zero-check-on-vaultaddress-in-depositandstake.yaml"
    WIKI_TITLE = "Missing zero check on vaultAddress in depositAndStake"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only for direct SteerPeriphery-shaped depositAndStake functions that rely on getPool(poolId).stakingToken == vaultAddress but do not reject vaultAddress == address(0). NOT_SUBMIT_READY."
    WIKI_EXPLOIT_SCENARIO = "depositAndStake compares getPool(poolId).stakingToken to vaultAddress without a visible vaultAddress zero-address guard."
    WIKI_RECOMMENDATION = "Do not promote from this fixture smoke alone. Add an explicit vaultAddress zero-address guard and validate full staking/vault registration semantics before submission."

    _PRECONDITIONS = []
    _MATCH = [{'function.name_matches': '^depositAndStake$'}, {'function.parameter_named': 'vaultAddress'}, {'function.body_contains_regex': '(?:require|assert)\\([^;{}]*(?:getPool\\([^;{}]*poolId[^;{}]*\\)\\.stakingToken\\s*==\\s*vaultAddress|vaultAddress\\s*==\\s*[^;{}]*getPool\\([^;{}]*poolId[^;{}]*\\)\\.stakingToken)'}, {'function.body_not_contains_regex': '(?:require|assert)\\([^;{}]*(?:vaultAddress\\s*!=\\s*(?:address\\(0x?0?\\)|0x0{40})|(?:address\\(0x?0?\\)|0x0{40})\\s*!=\\s*vaultAddress)'}]

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
                info = [f, f" — missing-zero-check-on-vaultaddress-in-depositandstake: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
