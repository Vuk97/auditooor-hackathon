"""
loan-claim-default-no-origin-check — generated from reference/patterns.dsl/loan-claim-default-no-origin-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py loan-claim-default-no-origin-check.yaml
Source: solodit/sherlock/cooler-H1-26353
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LoanClaimDefaultNoOriginCheck(AbstractDetector):
    ARGUMENT = "loan-claim-default-no-origin-check"
    HELP = "Batch claim-default / harvest path validates the factory-deployment of the container contract but not the originator of the individual loan/position. Attacker manufactures self-loans through the bare factory and mixes them in to inflate rewards and drain legitimate collateral."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/loan-claim-default-no-origin-check.yaml"
    WIKI_TITLE = "Batch claim-default iterates external-origin loans without checking originator"
    WIKI_DESCRIPTION = "A clearinghouse / keeper / rewards contract exposes a batch `claimDefaulted(address[] coolers, uint256[] loans)` that iterates each pair, calls into the container (`Cooler.claimDefaulted(id)`) and aggregates keeper rewards plus recovered collateral. The loop checks only that the container was deployed through the protocol's factory, which anyone can use to deploy their own instance. It does NOT ch"
    WIKI_EXPLOIT_SCENARIO = "Alice deploys 9 Coolers through `CoolerFactory.generateCooler()` (permissionless). She requests and self-funds 9 dust loans against her own collateral, defaults them. Bob borrows through the Clearinghouse, defaults. Alice calls `Clearinghouse.claimDefaulted([bobCooler, aliceC1, ..., aliceC9], [...])`. Each of Alice's loans credits her the 0.1 gOHM max keeper reward. She earns ~0.9 gOHM in keeper r"
    WIKI_RECOMMENDATION = "In every iteration, enforce `require(Cooler(coolers[i]).loans(loans[i]).lender == address(this), 'not clearinghouse loan')`. Consider routing all loan creation through a privileged function and tagging the loan struct with an `originator` field that's immutable after creation."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_func_matching': 'claimDefaulted|claimBatch|harvestDefaulted|batchClaim'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_param_of_type': '(address|uint256)\\[\\]'}, {'function.body_contains_regex': 'for\\s*\\(.*i\\s*<\\s*.*(length|len)'}, {'function.body_contains_regex': 'factory\\.created\\s*\\(|isRegistered\\s*\\(|registry\\s*\\['}, {'function.body_not_contains_regex': 'lender\\s*==\\s*address\\s*\\(\\s*this\\s*\\)|require\\s*\\([^)]*loan\\.(lender|originator|issuer)\\s*==|isClearinghouseLoan|originator\\s*=='}, {'function.body_contains_regex': '(keeperReward|totalCollateral|totalDebt|totalReward)\\s*\\+?='}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — loan-claim-default-no-origin-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
