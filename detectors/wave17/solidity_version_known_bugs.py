"""
solidity-version-known-bugs — generated from reference/patterns.dsl/solidity-version-known-bugs.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py solidity-version-known-bugs.yaml
Source: solodit-cluster/solc-known-bugs
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SolidityVersionKnownBugs(AbstractDetector):
    ARGUMENT = "solidity-version-known-bugs"
    HELP = "Contract pragma targets a Solidity compiler version with a known, disclosed bug (0.8.0-0.8.2 ABI-encoder V1 head overflow; 0.8.13 inline-assembly storage miscompile; 0.8.17 verbatim-assembly bug; 0.8.20 PUSH0 on non-Shanghai chains)."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/solidity-version-known-bugs.yaml"
    WIKI_TITLE = "Solidity compiler version has a known disclosed bug"
    WIKI_DESCRIPTION = "The Solidity team publishes a bugs.json of disclosed compiler bugs. This contract's pragma selects a version appearing on that list. Depending on the bug class, the impact ranges from silently corrupting ABI-encoded return data (0.8.0-0.8.2), miscompiling inline-assembly storage accesses (0.8.13), producing invalid bytecode for `verbatim` assembly (0.8.17), to emitting the PUSH0 opcode that breaks"
    WIKI_EXPLOIT_SCENARIO = "A contract pinned to ^0.8.13 uses inline assembly to write a storage slot during a user-facing function; due to the 0.8.13 optimizer bug, the write is elided under certain calling patterns, leaving the storage in an inconsistent state that an attacker can leverage for authorization bypass or accounting drift."
    WIKI_RECOMMENDATION = "Bump pragma to a version outside the known-bugs list (0.8.24+ at the time of writing) and re-audit any inline-assembly or verbatim usage. For 0.8.20, verify the deployment target EVM has Shanghai (PUSH0) activated or downgrade to 0.8.19. Consult https://soliditylang.org/blog/category/security-alerts"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'pragma\\s+solidity\\s+\\^?(0\\.8\\.0|0\\.8\\.1|0\\.8\\.2|0\\.8\\.13|0\\.8\\.17|0\\.8\\.20)\\b'}]
    _MATCH = [{'function.is_constructor': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — solidity-version-known-bugs: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
