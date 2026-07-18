"""
r94-loop-dvn-admin-execute-unilateral-no-multisig-no-timelock — generated from reference/patterns.dsl/r94-loop-dvn-admin-execute-unilateral-no-multisig-no-timelock.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-dvn-admin-execute-unilateral-no-multisig-no-timelock.yaml
Source: kelp-rseth-exploit-2026-04-18-banteg-postmortem
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopDvnAdminExecuteUnilateralNoMultisigNoTimelock(AbstractDetector):
    ARGUMENT = "r94-loop-dvn-admin-execute-unilateral-no-multisig-no-timelock"
    HELP = "r94-loop-dvn-admin-execute-unilateral-no-multisig-no-timelock"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-dvn-admin-execute-unilateral-no-multisig-no-timelock.yaml"
    WIKI_TITLE = "r94-loop-dvn-admin-execute-unilateral-no-multisig-no-timelock"
    WIKI_DESCRIPTION = "r94-loop-dvn-admin-execute-unilateral-no-multisig-no-timelock"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-dvn-admin-execute-unilateral-no-multisig-no-timelock"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(DVN|DesignatedVerifier|Attester|Oracle|Relayer)'}]
    _MATCH = [{'function.name_matches': '(?i)^(execute|executeAttestation|attest|adminAttest|postAttestation|publishAttestation|commitAttestation|emitPayloadVerified)$'}, {'function.source_matches_regex': '(onlyAdmin|onlyRole\\s*\\(\\s*ADMIN_ROLE|require\\s*\\(\\s*hasRole\\s*\\(\\s*ADMIN_ROLE|require\\s*\\(\\s*msg\\.sender\\s*==\\s*\\w*admin)'}, {'function.not_source_matches_regex': '(multisig|multiSig|MultiSig|timelock|TimeLock|TIMELOCK|signerQuorum|schnorrAggregatedSig|aggregatedSig|dvnSignerSet|gnosisSafe|GnosisSafe|thresholdCheck|require\\s*\\(\\s*\\w*signatures\\.length\\s*>=\\s*\\w*threshold|require\\s*\\(\\s*\\w*signatureCount\\s*>=\\s*(2|3|4))'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r94-loop-dvn-admin-execute-unilateral-no-multisig-no-timelock: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
