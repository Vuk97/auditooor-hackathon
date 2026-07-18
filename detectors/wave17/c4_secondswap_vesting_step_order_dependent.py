"""
c4-secondswap-vesting-step-order-dependent — generated from reference/patterns.dsl/c4-secondswap-vesting-step-order-dependent.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py c4-secondswap-vesting-step-order-dependent.yaml
Source: code4arena/2024-12-secondswap-H01
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class C4SecondswapVestingStepOrderDependent(AbstractDetector):
    ARGUMENT = "c4-secondswap-vesting-step-order-dependent"
    HELP = "Vesting listing/split does not snapshot stepsClaimed — reordering listings changes buyer claimable."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/c4-secondswap-vesting-step-order-dependent.yaml"
    WIKI_TITLE = "Vesting listing claimable depends on listing order"
    WIKI_DESCRIPTION = "A split/listing mechanism for vesting positions must fork the `stepsClaimed` counter per resulting portion at the moment of split. Sharing a global counter means step progress on one portion advances the other, so the order in which portions are listed changes what each subsequent buyer can claim."
    WIKI_EXPLOIT_SCENARIO = "SecondSwap 2024-12 H-01: after listing portion A, a claim on A advanced the shared step counter; subsequent buyer of portion B received less than expected because B read the post-claim step as its own starting point."
    WIKI_RECOMMENDATION = "On every split/list, store `stepsClaimedAtListing[portionId]` and compute claimable as `currentStep - stepsClaimedAtListing[portionId]`. Never mutate a shared counter."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'vesting|VestingMarketplace|stepsClaimed|listOrder'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(list|listPortion|createListing|splitVesting)'}, {'function.body_contains_regex': 'stepsClaimed|listOrder|lastStep|cumulativeStep'}, {'function.body_not_contains_regex': 'stepsClaimedAtListing|snapshotStep|_fixStepsOnSplit'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — c4-secondswap-vesting-step-order-dependent: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
