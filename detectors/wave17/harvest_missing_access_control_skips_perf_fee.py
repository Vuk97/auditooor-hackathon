"""
harvest-missing-access-control-skips-perf-fee — generated from reference/patterns.dsl/harvest-missing-access-control-skips-perf-fee.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py harvest-missing-access-control-skips-perf-fee.yaml
Source: code4arena/slice_ab-BakerFi-H02
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class HarvestMissingAccessControlSkipsPerfFee(AbstractDetector):
    ARGUMENT = "harvest-missing-access-control-skips-perf-fee"
    HELP = "harvest()/compound() has no access control, letting anyone snapshot the high-water mark at a zero-gain block so subsequent real gains dodge the performance fee."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/harvest-missing-access-control-skips-perf-fee.yaml"
    WIKI_TITLE = "Permissionless harvest lets callers dodge performance fee via HWM snapshot"
    WIKI_DESCRIPTION = "Vaults that charge a performance fee above a high-water mark rely on `harvest` being called at meaningful intervals so that fees are captured on realized gains. When harvest is public, an attacker can call it millions of times a day — at every zero-gain block — pushing the HWM up before the protocol can record the gain, so the performance fee sees `profit = 0` on the next legitimate harvest."
    WIKI_EXPLOIT_SCENARIO = "BakerFi vault accrues performance fee when `sharePrice > HWM`. Public `harvest()` snapshots HWM at every call. Anyone sandwiches a yield-bearing accrual: call `harvest()` pre-accrual (sets HWM), then call `harvest()` post-accrual but before the protocol's perf-fee keeper — most of the profit is captured by an intermediate HWM bump and the fee formula sees only the residual."
    WIKI_RECOMMENDATION = "Restrict harvest to a keeper role (`onlyKeeper`) or the vault owner. If permissionless harvest is a design goal, charge a flat caller reward + take a share of any gain at harvest-time, so the harvester's incentive is aligned with protocol revenue."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(harvest|compound|performanceFee|watermark|highWaterMark)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(harvest|compound|realize|settleRewards)$'}, {'function.body_contains_regex': '(highWaterMark|hwm|watermark|lastAccrued|lastProfit|sharePrice)\\s*='}, {'function.body_not_contains_regex': 'onlyOwner|onlyKeeper|onlyStrategist|hasRole|_checkRole|_requireKeeper|msg\\.sender\\s*==\\s*(owner|keeper|strategist)'}, {'function.has_modifier': {'includes': []}}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — harvest-missing-access-control-skips-perf-fee: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
