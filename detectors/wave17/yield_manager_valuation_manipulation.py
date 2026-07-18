"""
yield-manager-valuation-manipulation — generated from reference/patterns.dsl/yield-manager-valuation-manipulation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py yield-manager-valuation-manipulation.yaml
Source: auditooor-SKILL_ISSUE-223
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class YieldManagerValuationManipulation(AbstractDetector):
    ARGUMENT = "yield-manager-valuation-manipulation"
    HELP = "Yield manager backing asset valuation is manipulable via oracle timing or flash loans. Functions that compute totalAssets, totalSupply, or share price using a manipulable price source allow an attacker to mint excess shares or drain the vault."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/yield-manager-valuation-manipulation.yaml"
    WIKI_TITLE = "Yield manager valuation manipulation via manipulable oracle"
    WIKI_DESCRIPTION = "Functions like totalAssets, convertToShares, and convertToAssets compute share price using on-chain price feeds without adequate staleness checks or TWAP guards. An attacker can manipulate the oracle price through flash loans or oracle timing to mint excess shares at an artificially low price, diluting existing shareholdings."
    WIKI_EXPLOIT_SCENARIO = "Attacker takes a flash loan and manipulates the oracle price to artificially inflate the totalAssets() of a yield vault. They then deposit at the inflated share price, receiving more shares than they should. After unwinding the flash loan, the share price normalizes and the attacker redeems at fair value, pocketing the difference."
    WIKI_RECOMMENDATION = "Use TWAP (time-weighted average price) or implement staleness checks with require statements before using oracle prices. Ensure price sources have adequate liquidity incentives or commit-reveal schemes to prevent oracle manipulation."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(vault|share|asset|yield|manager)'}]
    _MATCH = [{'function.name_matches': '^(totalAssets|convertToShares|convertToAssets|getPrice|latestAnswer|latestRoundData)$'}, {'function.body_contains_regex': '(price|asset|share|valuation|oracle|feed)'}, {'function.not_body_contains_regex': 'require\\s*\\(\\s*.*\\s*>&&'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — yield-manager-valuation-manipulation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
