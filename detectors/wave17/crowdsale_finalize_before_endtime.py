"""
crowdsale-finalize-before-endtime — generated from reference/patterns.dsl/crowdsale-finalize-before-endtime.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py crowdsale-finalize-before-endtime.yaml
Source: solodit-cluster-C0034
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CrowdsaleFinalizeBeforeEndtime(AbstractDetector):
    ARGUMENT = "crowdsale-finalize-before-endtime"
    HELP = "Crowdsale finalize/close entry point does not check block.timestamp against the declared end-time — the operator can terminate the sale early, locking participants out of the remaining window."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/crowdsale-finalize-before-endtime.yaml"
    WIKI_TITLE = "Crowdsale finalize before advertised end-time"
    WIKI_DESCRIPTION = "A crowdsale / presale contract declares a public `endTime` / `closingTime` but its `finalize` (or `close`, `endSale`) entry point does not require `block.timestamp >= endTime` before flipping the sale to the terminal state. The privileged caller can finalize the sale at any point — freezing unsold tokens, locking refunds, or snatching proceeds — without the time guarantee users relied on when they"
    WIKI_EXPLOIT_SCENARIO = "Alice deposits ETH into the sale one day before the advertised two-week window ends. The owner — either out of convenience or malice — calls `finalize()` the next block. The sale terminates, Alice's refund path is locked behind `onlyAfterSale` gating that now returns success immediately, and the remaining vesting schedule snaps to the shortened window. If the finalize path also moves proceeds to a"
    WIKI_RECOMMENDATION = "Add `require(block.timestamp >= endTime)` (or the equivalent `hasEnded()` helper) as the first statement of every finalize/close/endSale entry point. For emergency shutdown paths, use a distinct name (`emergencyShutdown`) that is clearly NOT the normal lifecycle finalize and that routes refunds, not"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(Crowdsale|Presale|TokenSale|ICO|IDO|FairLaunch|saleEnd|crowdsaleEnd|presaleEnd|closingTime|endTime|hasEnded|isFinalized)'}, {'contract.has_state_var_matching': '(endTime|saleEnd|closingTime|presaleEnd|crowdsaleEnd|deadline)'}, {'contract.has_function_matching': '(finalize|close|endSale|finishSale)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(finalize|finalizeSale|close|closeSale|endSale|finishSale|finalizeCrowdsale|closeCrowdsale)$'}, {'function.writes_storage_matching': '(finalized|closed|ended|saleEnded|isActive)'}, {'function.body_not_contains_regex': 'block\\.timestamp\\s*(>=|>)\\s*(endTime|saleEnd|closingTime|presaleEnd|crowdsaleEnd|deadline)|now\\s*(>=|>)\\s*(endTime|saleEnd|closingTime|presaleEnd|crowdsaleEnd|deadline)|hasEnded\\s*\\(\\s*\\)|isEnded\\s*\\(\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(super\\.finalize|super\\.close|FinalizableCrowdsale\\.|emergencyShutdown|onlyEmergency|view\\s+returns|pure\\s+returns|require\\s*\\(\\s*!\\s*finalized|require\\s*\\(\\s*finalized\\s*==\\s*false)'}]

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
                info = [f, f" — crowdsale-finalize-before-endtime: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
