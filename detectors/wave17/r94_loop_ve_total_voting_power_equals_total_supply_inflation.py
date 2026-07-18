"""
r94-loop-ve-total-voting-power-equals-total-supply-inflation — generated from reference/patterns.dsl/r94-loop-ve-total-voting-power-equals-total-supply-inflation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-ve-total-voting-power-equals-total-supply-inflation.yaml
Source: solodit-57216-codehawks-raac-veraac
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopVeTotalVotingPowerEqualsTotalSupplyInflation(AbstractDetector):
    ARGUMENT = "r94-loop-ve-total-voting-power-equals-total-supply-inflation"
    HELP = "r94-loop-ve-total-voting-power-equals-total-supply-inflation"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-ve-total-voting-power-equals-total-supply-inflation.yaml"
    WIKI_TITLE = "r94-loop-ve-total-voting-power-equals-total-supply-inflation"
    WIKI_DESCRIPTION = "r94-loop-ve-total-voting-power-equals-total-supply-inflation"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-ve-total-voting-power-equals-total-supply-inflation"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(veToken|VotingEscrow|veRAAC|veLocked|VotingPower)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(getTotalVotingPower|totalVotingPower|getTotalVotes|totalVotes|globalVotingSupply|votingSupply)'}, {'function.source_matches_regex': '(return\\s+\\w*totalSupply\\s*\\(\\s*\\)|return\\s+this\\.totalSupply\\s*\\(\\s*\\)|return\\s+super\\.totalSupply\\s*\\(\\s*\\))'}, {'function.not_source_matches_regex': '(sumOfBiases|sumOfSlopes|globalBias|globalSlope|lockedVotingPowerSum|integrateSupply|sumOverLocks|epochTotalVotes)'}]

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
                info = [f, f" — r94-loop-ve-total-voting-power-equals-total-supply-inflation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
