"""
r94-loop-observer-untrusted-role — generated from reference/patterns.dsl/r94-loop-observer-untrusted-role.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-observer-untrusted-role.yaml
Source: loop-cycle-4-bridge-observer-untrusted-sibling
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopObserverUntrustedRole(AbstractDetector):
    ARGUMENT = "r94-loop-observer-untrusted-role"
    HELP = "r94-loop-observer-untrusted-role"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-observer-untrusted-role.yaml"
    WIKI_TITLE = "r94-loop-observer-untrusted-role"
    WIKI_DESCRIPTION = "r94-loop-observer-untrusted-role"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-observer-untrusted-role"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(observer|relayer|bridge|inbound|tracker|attest)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(markInbound|markInboundConfirmed|markInboundTx|markInboundProcessed|confirmDeposit|confirmInboundDeposit|confirmInbound|attestTransaction|attestInboundTx|attestDeposit|recordTx|recordInboundTx|recordDeposit|notifyInbound|notifyInboundTx|processInbound|processInboundTx|addInboundTx|addInbound|addInboundDeposit|relayInbound|relayInboundTx)$'}, {'function.source_matches_regex': 'onlyObserver|onlyRelayer|require\\s*\\(\\s*isObserver|\nhasRole\\s*\\(\\s*OBSERVER_ROLE|hasRole\\s*\\(\\s*RELAYER_ROLE\n'}, {'function.not_source_matches_regex': 'quorum|multiAttest|multiObserver|merkleProof|verifyProof|\nzkVerify|attestationCount|\\.verify\\s*\\(|\nsignatures\\.length\\s*>=|threshold\n'}, {'function.not_source_matches_regex': 'require\\s*\\(\\s*\\w*(Success|Confirmed|Executed|Final)|\nsourceTxStatus|txStatus\\s*==|(.|)\\.status\\s*==\\s*\\d\n'}]

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
                info = [f, f" — r94-loop-observer-untrusted-role: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
