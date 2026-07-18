"""
c4-deploy-undeploy-accounting-asymmetry — generated from reference/patterns.dsl/c4-deploy-undeploy-accounting-asymmetry.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py c4-deploy-undeploy-accounting-asymmetry.yaml
Source: code4arena/slice_ab-BakerFi-LoopFi
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class C4DeployUndeployAccountingAsymmetry(AbstractDetector):
    ARGUMENT = "c4-deploy-undeploy-accounting-asymmetry"
    HELP = "Strategy increments `_deployedAmount` / `lastBalance` on deploy but the corresponding `undeploy`/`redeem` path forgets to decrement. Accounting drifts; performance fee / share price permanently wrong."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/c4-deploy-undeploy-accounting-asymmetry.yaml"
    WIKI_TITLE = "deploy increments accounting; undeploy does not decrement"
    WIKI_DESCRIPTION = "Paired bookkeeping variables must be mutated symmetrically. A strategy where `deploy()` does `_deployedAmount += x` but `undeploy()` omits `_deployedAmount -= x` yields stale accounting, leading to zero or inverted performance-fee calcs."
    WIKI_EXPLOIT_SCENARIO = "Strategy deploys 100 ETH to Aave. `_deployedAmount = 100`. User calls `undeploy(50)`; ETH returns but `_deployedAmount` stays 100. Next `harvest` computes `profit = currentAssets - _deployedAmount` incorrectly, minting 0 performance fee despite real yield."
    WIKI_RECOMMENDATION = "Write both directions in the same audited helper: `_setDeployedAmount(+/-)`. Prefer CEI-style explicit state updates."

    _PRECONDITIONS = [{'contract.source_matches_regex': '_deployedAmount|lastBalance|_deployed|totalDeployed'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(undeploy|withdraw|redeem|exit|divest)'}, {'function.body_contains_regex': 'safeTransfer|_transferOut|\\.transfer\\s*\\(|redeem\\s*\\('}, {'function.body_not_contains_regex': '(_deployedAmount|lastBalance|_deployed|totalDeployed)\\s*(-=|=\\s*\\w+\\s*-|=\\s*_\\w+\\s*\\.\\s*sub)'}, {'function.contract_has_source_matching': '(_deployedAmount|lastBalance|_deployed|totalDeployed)\\s*(\\+=|=\\s*\\w+\\s*\\+)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — c4-deploy-undeploy-accounting-asymmetry: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
