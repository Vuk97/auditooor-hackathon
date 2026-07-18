"""
silo-utilization-exceeds-100-percent-inflates-interest — generated from reference/patterns.dsl/silo-utilization-exceeds-100-percent-inflates-interest.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py silo-utilization-exceeds-100-percent-inflates-interest.yaml
Source: auditooor-R76-immunefi-silo-$100k
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SiloUtilizationExceeds100PercentInflatesInterest(AbstractDetector):
    ARGUMENT = "silo-utilization-exceeds-100-percent-inflates-interest"
    HELP = "Interest-rate model allows utilization > 100% when total borrows exceed tracked deposits (via token donation). Rate curve extrapolates off the end of its intended range, producing astronomical compound rates."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/silo-utilization-exceeds-100-percent-inflates-interest.yaml"
    WIKI_TITLE = "Utilization rate uncapped — donation-induced >100% utilization inflates interest"
    WIKI_DESCRIPTION = "Two-variable interest-rate models compute `utilization = totalBorrows / totalDeposits` and feed this into a rate curve that typically caps at some max APR at 100% utilization. If the model does not clamp utilization to <= 1.0, a donation attack (sending tokens directly to the market without calling deposit()) can push `totalBorrows > totalDeposits`. The rate curve extrapolates — often exponentiall"
    WIKI_EXPLOIT_SCENARIO = "Silo's BaseSilo._accrueInterest didn't cap utilization. Attacker targeted a low-liquidity market: deposited 1 wei, donated tokens (now totalBorrows > totalDeposits after someone borrowed), let accrueInterest run → utilization >100%, rate spiked to 5000% APR. Attacker's 1 wei deposit compounded to massive share of the asset, borrowed 450k XAI against it. $3M at risk; $100k bounty. Fix: `utilization"
    WIKI_RECOMMENDATION = "Always clamp utilization to [0, 1]: `uint256 util = totalBorrows.mulDiv(1e18, totalDeposits).min(1e18);`. Clamp the rate output to a hard `MAX_RATE` (e.g. 1000% APR). Never compute interest against a live `balanceOf(this)` — use `totalDeposits` bookkeeping that only changes on deposit/withdraw/repay"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.is_lending_market': True}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.name_matches': '(?i)_accrueInterest|updateIndexes|_getInterestRate|calcUtilization'}, {'function.body_contains_regex': '(?i)utilization\\s*=|borrows\\s*\\*\\s*\\w+\\s*/\\s*deposits|totalBorrows\\s*\\*\\s*1e18\\s*/\\s*totalDeposits'}, {'function.body_not_contains_regex': '(?i)min\\s*\\(\\s*\\w+,\\s*(?:1e18|PRECISION|100)|Math\\.min|utilization\\s*>\\s*(?:1e18|ONE)\\s*\\?\\s*(?:1e18|ONE)|require\\s*\\(\\s*utilization\\s*<='}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — silo-utilization-exceeds-100-percent-inflates-interest: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
