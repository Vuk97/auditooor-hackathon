"""
dos-cap-flag-or-estimation-oneway-exhaustion - generated from reference/patterns.dsl/dos-cap-flag-or-estimation-oneway-exhaustion.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py dos-cap-flag-or-estimation-oneway-exhaustion.yaml
Source: rwrq-dos-cap-weakening-36895fa0698a
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DosCapFlagOrEstimationOnewayExhaustion(AbstractDetector):
    ARGUMENT = "dos-cap-flag-or-estimation-oneway-exhaustion"
    HELP = "Receipt flags or cross-chain gas caps are consumed one way, with no reset, retry, or destination overhead. Dust receipt or undercounted gas can permanently block later execution."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/dos-cap-flag-or-estimation-oneway-exhaustion.yaml"
    WIKI_TITLE = "One-way receipt flag or gas-cap exhaustion"
    WIKI_DESCRIPTION = "A protocol can weaken a liveness cap by turning a cheap event into a permanent state transition. Examples include a receipt flag set by a dust arrival that gates later claims, or a cross-chain gas limit forwarded exactly as supplied without destination-chain overhead. The common bug class is one-way exhaustion: the attacker or caller can consume the flag, cap, or estimate, but the protocol has no reset, retry, or overhead-aware correction path."
    WIKI_EXPLOIT_SCENARIO = "An attacker sends a dust receipt to a victim, setting `hasReceived[victim] = true`; the later claim path rejects any address with that sticky flag. In a sibling cross-chain case, a caller supplies `gasLimit` estimated on the source chain and the bridge forwards it unchanged, so destination delivery runs out of gas and no retry gas path exists."
    WIKI_RECOMMENDATION = "Do not make receipt flags or caller supplied gas estimates one-way liveness gates. Scope flags by message id and amount, expose a reset or retry path, and add destination-aware gas overhead before dispatch."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(bridge|cross.?chain|message|receipt|receive|claim|deliver|gasLimit|gas limit|cap|quota|limit|processed|hasReceived|isReceived|isLocked|isHolder|isBanned|isBridgedTokenHolder)'}, {'contract.source_matches_regex': '(?i)(hasReceived|received|processed|delivered|consumed|locked|isHolder|isBanned|isBridgedTokenHolder|_gasLimit|gasLimit|executionGas|callbackGas|nativeCap|maxGas|cap)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.source_matches_regex': '(?is)((hasReceived|received|processed|delivered|consumed|locked|isLocked|isReceived|isHolder|isBanned|isBridgedTokenHolder)\\s*\\[\\s*[^]]+\\s*\\]\\s*=\\s*true)|((sendMessage|sendToL2|sendCrossChain|crossChainSend|dispatch|lzSend|quoteSend|estimateGas|call\\{gas:)[\\s\\S]{0,300}(_gasLimit|gasLimit|executionGas|callbackGas|maxGas|nativeCap|cap))'}, {'function.source_matches_regex': '(?i)(bridge|cross.?chain|message|receipt|receive|claim|deliver|gas|cap|limit|processed|locked)'}, {'contract.has_no_function_body_matching': '(?is)((hasReceived|received|processed|delivered|consumed|locked|isLocked|isReceived|isHolder|isBanned|isBridgedTokenHolder)\\s*\\[[^]]+\\]\\s*=\\s*false|delete\\s+(hasReceived|received|processed|delivered|consumed|locked|isLocked|isReceived|isHolder|isBanned|isBridgedTokenHolder)\\s*\\[|reset[A-Za-z0-9_]*\\(|clear[A-Za-z0-9_]*\\(|retry[A-Za-z0-9_]*\\(|resend[A-Za-z0-9_]*\\(|increaseGas|addGas|gasBuffer|INTRINSIC_GAS|OVERHEAD|OVERHEAD_GAS|_minGasPerByte|estimateIntrinsic|minGasPerByte|requiredGas|refund|excess)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" - dos-cap-flag-or-estimation-oneway-exhaustion: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
