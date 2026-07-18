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
    HELP = "Strategy increments `_deployedAmount` / `lastBalance` on deploy, then value exits through `undeploy` / `redeem` without mutating the same accounting slot. Stored deployed balance drifts upward and downstream fee/share math reads stale state."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/c4-deploy-undeploy-accounting-asymmetry.yaml"
    WIKI_TITLE = "deploy increments accounting; undeploy does not decrement"
    WIKI_DESCRIPTION = "Paired bookkeeping variables must be mutated symmetrically. This detector looks for contracts that have a deploy-like entrypoint writing `_deployedAmount` / `lastBalance` / `totalDeployed`, then an undeploy-like exit path that transfers or redeems value but never writes the same storage slot. The result is stale accounting: deployed capital appears larger than reality, skewing performance fees, sh"
    WIKI_EXPLOIT_SCENARIO = "Strategy deploys 100 ETH into a market and records `_deployedAmount = 100`. Later `undeploy(40)` redeems assets and transfers them out to the vault, but never decrements `_deployedAmount`. The next harvest or NAV calculation still believes 100 ETH is deployed even though only 60 ETH remains in the strategy. Fees can be underpaid, profits can be masked, or utilization-driven limits can be miscomput"
    WIKI_RECOMMENDATION = "Keep deploy and undeploy bookkeeping in the same reviewed helper or assert the accounting delta on every exit path. If the strategy uses `_deployedAmount`, `lastBalance`, or a similar cached deployed-capital slot, every transfer/redeem/undeploy branch that returns principal must unwind the slot in t"

    _PRECONDITIONS = [{'contract.has_state_var_matching': '(?i)^(_?deployed(?:Amount|Balance)?|lastBalance|totalDeployed|managedAssets)$'}, {'contract.has_function_body_matching': '(?is)function\\s+(deploy|invest|supply|allocate|lend)[A-Za-z0-9_]*\\s*\\([^)]*\\)[^{;]*\\{[^{}]{0,500}?(_?deployed(?:Amount|Balance)?|lastBalance|totalDeployed|managedAssets)\\s*(\\+=|=\\s*[^;]{0,120}\\+)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(undeploy|withdraw|redeem|exit|divest)[A-Za-z0-9_]*$'}, {'function.is_mutating': True}, {'function.body_contains_regex': '(?i)(safeTransfer|_transferOut|\\.transfer\\s*\\(|redeem\\s*\\()'}, {'function.body_not_contains_regex': '(?i)(_?deployed(?:Amount|Balance)?|lastBalance|totalDeployed|managedAssets)\\s*(-=|=\\s*[^;]{0,120}-)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
