"""
r94-loop-royalty-distribution-rounding-dust-siphon — generated from reference/patterns.dsl/r94-loop-royalty-distribution-rounding-dust-siphon.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-royalty-distribution-rounding-dust-siphon.yaml
Source: solodit-48857-ottersec-monument
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopRoyaltyDistributionRoundingDustSiphon(AbstractDetector):
    ARGUMENT = "r94-loop-royalty-distribution-rounding-dust-siphon"
    HELP = "r94-loop-royalty-distribution-rounding-dust-siphon"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-royalty-distribution-rounding-dust-siphon.yaml"
    WIKI_TITLE = "r94-loop-royalty-distribution-rounding-dust-siphon"
    WIKI_DESCRIPTION = "r94-loop-royalty-distribution-rounding-dust-siphon"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-royalty-distribution-rounding-dust-siphon"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(Royalty|RoyaltyInfo|Artifact|RevenueShare|Monument|Splitter)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(distributeRoyalties|payRoyalties|payoutRoyalties|distributeRevenue|splitRevenue|distributeFees|payoutShares|distributeShares)'}, {'function.source_matches_regex': '(amount\\s*\\*\\s*[\\w\\.]*(bps|permyriad|share|weight)\\s*\\/|total\\s*\\*\\s*[\\w\\.]*share\\s*\\/\\s*(10000|TOTAL))'}, {'function.not_source_matches_regex': '(dust\\s*=|residual\\s*=|leftover\\s*=\\s*amount\\s*-|remaining\\s*=\\s*amount\\s*-|lastShare\\s*=\\s*amount\\s*-|sendDustToTreasury|sendResidual|accumulatedDust|if\\s*\\(\\s*i\\s*==\\s*\\w*\\.length\\s*-\\s*1|lastRecipient\\s*=\\s*amount\\s*-)'}]

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
                info = [f, f" — r94-loop-royalty-distribution-rounding-dust-siphon: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
