"""
r94-loop-vulnerable-ecdsa-library-eip2098-malleable-version — generated from reference/patterns.dsl/r94-loop-vulnerable-ecdsa-library-eip2098-malleable-version.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-vulnerable-ecdsa-library-eip2098-malleable-version.yaml
Source: solodit-50225-halborn-biconomy-smart-wallet-v2
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopVulnerableEcdsaLibraryEip2098MalleableVersion(AbstractDetector):
    ARGUMENT = "r94-loop-vulnerable-ecdsa-library-eip2098-malleable-version"
    HELP = "r94-loop-vulnerable-ecdsa-library-eip2098-malleable-version"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-vulnerable-ecdsa-library-eip2098-malleable-version.yaml"
    WIKI_TITLE = "r94-loop-vulnerable-ecdsa-library-eip2098-malleable-version"
    WIKI_DESCRIPTION = "r94-loop-vulnerable-ecdsa-library-eip2098-malleable-version"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-vulnerable-ecdsa-library-eip2098-malleable-version"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = {'contract.source_matches_regex': '(ECDSA|Signature|Wallet|Biconomy|Smart)', 'function.name_matches': '(?i)(recoverSigner|verify|verifySignature|validateUserOp|isValidSignature|_validateSignature)'}
    _MATCH = {'function.source_matches_regex': '(ECDSA\\.recover\\s*\\(\\s*\\w+\\s*,\\s*\\w+\\s*\\)|ECDSA::recover\\s*\\(\\s*\\w+\\s*,\\s*\\w+\\s*\\))', 'function.not_source_matches_regex': '(ECDSA\\.recover\\s*\\(\\s*\\w+\\s*,\\s*v\\s*,\\s*r\\s*,\\s*s\\s*\\)|ECDSA\\.tryRecover\\s*\\(\\s*\\w+\\s*,\\s*v\\s*,\\s*r\\s*,\\s*s\\s*\\)|openzeppelin-contracts\\s*=\\s*"\\s*\\^?\\s*4\\.7\\.[3-9]|solady|ECDSA\\w+Cached)'}

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
                info = [f, f" — r94-loop-vulnerable-ecdsa-library-eip2098-malleable-version: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
