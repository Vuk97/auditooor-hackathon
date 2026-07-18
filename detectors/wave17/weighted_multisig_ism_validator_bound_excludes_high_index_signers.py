"""
weighted-multisig-ism-validator-bound-excludes-high-index-signers — generated from reference/patterns.dsl/weighted-multisig-ism-validator-bound-excludes-high-index-signers.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py weighted-multisig-ism-validator-bound-excludes-high-index-signers.yaml
Source: auditooor-R73-fixdiff-mined-hyperlane-9eefa2d95a
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class WeightedMultisigIsmValidatorBoundExcludesHighIndexSigners(AbstractDetector):
    ARGUMENT = "weighted-multisig-ism-validator-bound-excludes-high-index-signers"
    HELP = "Weighted-multisig verify loops use Math.min(validators.length, signatureCount) as both the outer signature-loop bound AND the inner validator-search bound. The inner bound must be validators.length, not the min — otherwise a single high-weight validator (index > signatureCount) cannot be reached by "
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/weighted-multisig-ism-validator-bound-excludes-high-index-signers.yaml"
    WIKI_TITLE = "WeightedMultisigIsm non-sequential signer bug — validator pointer cannot reach high-index signers"
    WIKI_DESCRIPTION = "Weighted multisig verification walks two pointers: signatureIndex over the ordered signatures, and validatorIndex over the validator set (assumed sorted by signingAddress). A signer's weight contributes only if the validator-walk pointer lands on them. Hyperlane's original implementation set `_validatorCount = Math.min(_validators.length, signatureCount(_metadata))` and used `_validatorCount` to b"
    WIKI_EXPLOIT_SCENARIO = "Validator set: [A (5% weight), B (5%), C (5%), D (5%), E (80%)] at indices 0..4. Threshold 50%. Only E signs — legitimate: E's 80% exceeds 50%. signatureCount = 1, so _validatorCount = min(5, 1) = 1. Loop: signatureIndex=0, recover signer = E. Inner while: _validatorIndex starts 0, validators[0].signingAddress = A != E, ++_validatorIndex → 1; now _validatorIndex (1) < _validatorCount (1) is FALSE,"
    WIKI_RECOMMENDATION = "Bound the outer signature loop by signatureCount (so we don't OOB-read metadata), and bound the inner validator-search loop by validators.length (so we can reach any validator index). Add a test that deploys a validator set where only the last-index validator has enough weight and signs alone — this"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'WeightedMultisig|ValidatorInfo|weight|thresholdWeight'}]
    _MATCH = [{'function.kind': 'internal'}, {'function.name_matches': '^(verify|_verify|verifySignatures|digestAndVerify)$'}, {'function.body_contains_regex': 'Math\\.min\\s*\\(\\s*_?validators\\.length\\s*,\\s*signatureCount\\s*\\('}, {'function.body_contains_regex': '_?validatorIndex\\s*<\\s*_?validatorCount'}, {'function.body_not_contains_regex': '_?validatorIndex\\s*<\\s*_?validators\\.length'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — weighted-multisig-ism-validator-bound-excludes-high-index-signers: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
