"""
ec-validate-signature-jacobian-conversion-on-projective — generated from reference/patterns.dsl/ec-validate-signature-jacobian-conversion-on-projective.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ec-validate-signature-jacobian-conversion-on-projective.yaml
Source: lisa-mine-r99-case-06679-c4-ens-2023-04
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EcValidateSignatureJacobianConversionOnProjective(AbstractDetector):
    ARGUMENT = "ec-validate-signature-jacobian-conversion-on-projective"
    HELP = "EllipticCurve `validateSignature` converts a point produced by a projective-coordinate routine into affine coordinates using the JACOBIAN formula `X_a = X_j * (Z_j^-1)^2` (square the Z-inverse). Projective-to-affine is `X_a = X_p * Z_p^-1` (no squaring). Mixing the two coordinate systems silently pr"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ec-validate-signature-jacobian-conversion-on-projective.yaml"
    WIKI_TITLE = "EC validateSignature applies Jacobian-to-affine formula on projective output"
    WIKI_DESCRIPTION = "Pattern fires on EC `validateSignature` / `verifySignature` helpers that compute affine X / Y as `pointArr[0] * z_inv * z_inv` (square of Z-inverse) when the upstream point arithmetic produced PROJECTIVE coordinates rather than Jacobian. The two systems differ: Jacobian uses `(X, Y, Z)` with `(x_aff, y_aff) = (X/Z^2, Y/Z^3)`; projective uses `(X, Y, Z)` with `(x_aff, y_aff) = (X/Z, Y/Z)`. The Z-in"
    WIKI_EXPLOIT_SCENARIO = "ENS DNSSEC oracle uses a projective `_jAdd / _jDouble` library to compute `R = uG + vQ` and then converts via Jacobian formula. Currently masked by a redundant Z-multiplication elsewhere. After the team patches the redundant multiplication (treating it as the bug), `validateSignature` will silently corrupt every check: legitimate DNS proofs fail, name-resolution stalls, or — depending on which bra"
    WIKI_RECOMMENDATION = "Audit the upstream point arithmetic; tag each intermediate point with the coordinate system it lives in (`Jacobian` or `Projective`). Use `X_a = X_p * Z_p^-1, Y_a = Y_p * Z_p^-1` for projective points; `X_a = X_j * Z_j^-2, Y_a = Y_j * Z_j^-3` for Jacobian. Better: standardise the entire library on o"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'EllipticCurve|jAdd|jDouble|jacobian|projective'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': 'validateSignature|verifySignature|ecVerify|verifyECDSA|verify[A-Z]*Sig'}, {'function.body_contains_regex': '\\binverseMod\\s*\\(\\s*[A-Za-z_][A-Za-z0-9_]*\\s*\\[\\s*2\\s*\\]|inverseMod\\s*\\(\\s*Z[ _]*[a-z]*\\s*,'}, {'function.body_contains_regex': 'mulmod\\s*\\(\\s*[A-Za-z_][\\w\\[\\]\\s]*,\\s*mulmod\\s*\\(\\s*[A-Za-z_][\\w]*\\s*,\\s*[A-Za-z_][\\w]*|[A-Za-z_]+\\s*\\*\\s*[A-Za-z_]*[Zz][Ii]nv\\s*\\*\\s*[A-Za-z_]*[Zz][Ii]nv|X_a\\s*=\\s*[A-Za-z_][\\w\\[\\]]*\\s*\\*\\s*Z_inv\\s*\\*\\s*Z_inv'}, {'function.body_not_contains_regex': 'projectiveToAffine|projective_to_affine|isProjective\\s*=\\s*true|jacobianToAffine\\s+only|toAffineFromProjective'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" — ec-validate-signature-jacobian-conversion-on-projective: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
