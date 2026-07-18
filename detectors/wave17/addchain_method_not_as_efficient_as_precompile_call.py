"""
addchain-method-not-as-efficient-as-precompile-call — generated from reference/patterns.dsl/addchain-method-not-as-efficient-as-precompile-call.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py addchain-method-not-as-efficient-as-precompile-call.yaml
Source: zellic audit SolBLS - Zellic Audit Report
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AddchainMethodNotAsEfficientAsPrecompileCall(AbstractDetector):
    ARGUMENT = "addchain-method-not-as-efficient-as-precompile-call"
    HELP = "In audits/internal_audit_july_2024.md, it is said that calling the Ethereum modexp precompile at 0x05 consumes around 14k gas. While the addchain method consumes around 7k gas per call, for functions inverse and sqrt, it is better to use the addchain compared to the precompile. One of the most expen"
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/addchain-method-not-as-efficient-as-precompile-call.yaml"
    WIKI_TITLE = "Addchain method not as efficient as precompile call"
    WIKI_DESCRIPTION = "In audits/internal_audit_july_2024.md, it is said that calling the Ethereum modexp precompile at 0x05 consumes around 14k gas. While the addchain method consumes around 7k gas per call, for functions inverse and sqrt, it is better to use the addchain compared to the precompile. One of the most expensive operations is calling the modexp precompile (0x05) for exponentiation. Instead, use the addchai"
    WIKI_EXPLOIT_SCENARIO = "Per audit finding: In audits/internal_audit_july_2024.md, it is said that calling the Ethereum modexp precompile at 0x05 consumes around 14k gas. While the addchain method consumes around 7k gas per call, for functions inverse and sqrt, it is better to use the addchain compared to the precompile. One of the most expensive operations is calling the modexp precompile (0x05) for exponentiation. Inste"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = []
    _MATCH = [{'function.name_matches': 'bigModExp', 'function.body_not_contains_regex': 'require\\s*\\(', 'function.not_slither_synthetic': True, 'function.not_in_skip_list': True}]

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
                info = [f, f" — addchain-method-not-as-efficient-as-precompile-call: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
