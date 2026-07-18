"""
r94-loop-layerzero-remote-transfer-caller-supplied-from-unauth-pull — generated from reference/patterns.dsl/r94-loop-layerzero-remote-transfer-caller-supplied-from-unauth-pull.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-layerzero-remote-transfer-caller-supplied-from-unauth-pull.yaml
Source: solodit-31064-sherlock-tapioca-usdo
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopLayerzeroRemoteTransferCallerSuppliedFromUnauthPull(AbstractDetector):
    ARGUMENT = "r94-loop-layerzero-remote-transfer-caller-supplied-from-unauth-pull"
    HELP = "r94-loop-layerzero-remote-transfer-caller-supplied-from-unauth-pull"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-layerzero-remote-transfer-caller-supplied-from-unauth-pull.yaml"
    WIKI_TITLE = "r94-loop-layerzero-remote-transfer-caller-supplied-from-unauth-pull"
    WIKI_DESCRIPTION = "r94-loop-layerzero-remote-transfer-caller-supplied-from-unauth-pull"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-layerzero-remote-transfer-caller-supplied-from-unauth-pull"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(USDO|OFT|TOFT|LayerZero|CrossChain|mTOFT|Remote)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(remoteTransfer|crossChainTransfer|receiveRemoteTransfer|executeRemoteTransfer|handleRemoteTransfer|lzReceiveTransfer|_creditTo|creditAndTransfer)'}, {'function.source_matches_regex': '(transferFrom\\s*\\(|_burn\\s*\\(\\s*\\w*from|burnFrom\\s*\\(\\s*\\w*from|balances\\[\\s*\\w*from\\s*\\]\\s*-=)'}, {'function.not_source_matches_regex': '(from\\s*=\\s*abi\\.decode\\s*\\(\\s*\\w*payload|\\(from,\\s*[^\\)]*\\)\\s*=\\s*abi\\.decode\\s*\\(\\s*\\w*payload|from\\s*=\\s*msg\\.sender|from\\s*=\\s*_msgSender\\s*\\(\\s*\\)|require\\s*\\(\\s*\\w*from\\s*==\\s*msg\\.sender|require\\s*\\(\\s*\\w*from\\s*==\\s*_msgSender|readFromPayload|parseFromPayload)'}]

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
                info = [f, f" — r94-loop-layerzero-remote-transfer-caller-supplied-from-unauth-pull: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
