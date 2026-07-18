"""
r94-loop-vesting-revoke-freezes-already-vested-unclaimed — generated from reference/patterns.dsl/r94-loop-vesting-revoke-freezes-already-vested-unclaimed.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-vesting-revoke-freezes-already-vested-unclaimed.yaml
Source: solodit-59721-quantstamp-tokenops-tokenvesting
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopVestingRevokeFreezesAlreadyVestedUnclaimed(AbstractDetector):
    ARGUMENT = "r94-loop-vesting-revoke-freezes-already-vested-unclaimed"
    HELP = "r94-loop-vesting-revoke-freezes-already-vested-unclaimed"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-vesting-revoke-freezes-already-vested-unclaimed.yaml"
    WIKI_TITLE = "r94-loop-vesting-revoke-freezes-already-vested-unclaimed"
    WIKI_DESCRIPTION = "r94-loop-vesting-revoke-freezes-already-vested-unclaimed"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-vesting-revoke-freezes-already-vested-unclaimed"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(Vesting|TokenVesting|Grant|TokenOps|Escrow)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(revokeGrant|revokeVesting|cancelGrant|terminateVesting|adminRevoke)'}, {'function.source_matches_regex': '(grant\\.(totalAmount|allocated|remaining)\\s*=\\s*0|grants\\s*\\[\\s*\\w+\\s*\\]\\s*=\\s*\\w*Grant\\s*\\(\\s*\\)|delete\\s+grants\\s*\\[|grant\\.revoked\\s*=\\s*true)'}, {'function.not_source_matches_regex': '(sendVestedToBeneficiary|payAlreadyVested|transfer\\s*\\(\\s*\\w*beneficiary\\s*,\\s*\\w*(alreadyVested|vestedAmount|releasedButNotClaimed)|settleVestedBeforeRevoke|finalPayout)'}]

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
                info = [f, f" — r94-loop-vesting-revoke-freezes-already-vested-unclaimed: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
