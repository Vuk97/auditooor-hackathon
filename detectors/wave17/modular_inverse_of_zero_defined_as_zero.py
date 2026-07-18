"""
modular-inverse-of-zero-defined-as-zero — generated from reference/patterns.dsl/modular-inverse-of-zero-defined-as-zero.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py modular-inverse-of-zero-defined-as-zero.yaml
Source: solodit-26821-consensys-linea-plonk-verifier
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ModularInverseOfZeroDefinedAsZero(AbstractDetector):
    ARGUMENT = "modular-inverse-of-zero-defined-as-zero"
    HELP = "modular-inverse-of-zero-defined-as-zero"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/modular-inverse-of-zero-defined-as-zero.yaml"
    WIKI_TITLE = "modular-inverse-of-zero-defined-as-zero"
    WIKI_DESCRIPTION = "modular-inverse-of-zero-defined-as-zero"
    WIKI_EXPLOIT_SCENARIO = "modular-inverse-of-zero-defined-as-zero"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(Verifier|Plonk|Groth16|Bn254|BN256|BLS|Pairing|Field|Fr|Fp|KZG)'}]
    _MATCH = [{'function.kind': 'internal_or_private_or_public'}, {'function.name_matches': '(?i)(inverse|modInverse|invMod|finv|^inv$|_inv$)'}, {'function.source_matches_regex': '(expmod|expMod|modExp|staticcall\\s*\\(\\s*gas\\s*\\(\\s*\\)\\s*,\\s*0x0?5|p\\s*-\\s*2|FIELD_MODULUS\\s*-\\s*2|R_MOD\\s*-\\s*2|PRIME\\s*-\\s*2)'}, {'function.not_source_matches_regex': '(require\\s*\\(\\s*\\w+\\s*!=\\s*0|require\\s*\\(\\s*\\w+\\s*>\\s*0|if\\s*\\(\\s*\\w+\\s*==\\s*0\\s*\\)\\s*(revert|return|assembly)|assert\\s*\\(\\s*\\w+\\s*!=\\s*0)'}]

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
                info = [f, f" — modular-inverse-of-zero-defined-as-zero: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
