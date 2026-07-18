"""
r94-loop-batch-claim-no-used-flag-params-replay — generated from reference/patterns.dsl/r94-loop-batch-claim-no-used-flag-params-replay.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-batch-claim-no-used-flag-params-replay.yaml
Source: solodit-36240-codehawks-beanstalk-finale
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopBatchClaimNoUsedFlagParamsReplay(AbstractDetector):
    ARGUMENT = "r94-loop-batch-claim-no-used-flag-params-replay"
    HELP = "r94-loop-batch-claim-no-used-flag-params-replay"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-batch-claim-no-used-flag-params-replay.yaml"
    WIKI_TITLE = "r94-loop-batch-claim-no-used-flag-params-replay"
    WIKI_DESCRIPTION = "r94-loop-batch-claim-no-used-flag-params-replay"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-batch-claim-no-used-flag-params-replay"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = {'contract.source_matches_regex': '(BatchClaim|BatchRedeem|Claim|MerkleClaim|Beanstalk)', 'function.name_matches': '(?i)(redeemDepositsAndInternalBalances|redeemBatch|batchClaim|claimBatch|executeBatchClaim|redeemInternalBalances)', 'function.source_matches_regex': '(verifyProof|merkleProof|params\\.claim|claimParams|paramsHash|batchProof)', 'function.not_source_matches_regex': '(used\\s*\\[\\s*\\w*(hash|params|id)\\s*\\]\\s*=\\s*true|claimed\\s*\\[\\s*\\w*leaf\\s*\\]\\s*=\\s*true|usedParams\\.insert|processedBatches\\.insert|claimedParams\\s*\\[|isConsumed|markConsumed|usedRoots\\[)'}
    _MATCH = ['contract.source_matches_regex', 'function.name_matches', 'function.source_matches_regex', 'function.not_source_matches_regex']

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
                info = [f, f" — r94-loop-batch-claim-no-used-flag-params-replay: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
