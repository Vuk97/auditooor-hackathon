"""
cap-enforced-at-entry-not-settlement — generated from reference/patterns.dsl/cap-enforced-at-entry-not-settlement.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py cap-enforced-at-entry-not-settlement.yaml
Source: code4arena-2025-11-megapot-H-03
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CapEnforcedAtEntryNotSettlement(AbstractDetector):
    ARGUMENT = "cap-enforced-at-entry-not-settlement"
    HELP = "Pool / vault cap is enforced at deposit but settlement / distribution paths credit the pool balance without a cap check — invariant silently breaks and governance loses ability to shrink the cap."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/cap-enforced-at-entry-not-settlement.yaml"
    WIKI_TITLE = "Cap enforced at deposit but bypassed by settlement accruals"
    WIKI_DESCRIPTION = "A vault / lottery / LP pool exposes a governance-set cap (`lpPoolCap`, `poolCap`, `depositCap`) that is diligently enforced by the deposit / mint / supply path (`require(pool + amount <= cap)`). However, a separate state-mutating path — settlement of a draw, distribution of profits, booking of winnings, rebalance from a sibling vault — credits the pool state field (`lpPool += amount`, `totalAssets"
    WIKI_EXPLOIT_SCENARIO = "A lottery protocol has `lpPoolCap = 1000 ETH`. LPs deposit up to 1000 ETH via `depositToLP`. Over subsequent draws, `settleDraw()` credits winnings: unclaimed-jackpot dust, retained rake, referral kickbacks flow into `lpPool`. After 10 draws, `lpPool = 1100 ETH > lpPoolCap`. (1) Governance decides the LP pool has gotten too risky and proposes `setLPPoolCap(800)`. The setter has `require(newCap >= "
    WIKI_RECOMMENDATION = "Every path that credits a capped balance must either (a) check the cap and route the overflow to a separate pool (treasury, insurance fund, surplus buffer) — `if (lpPool + amount > cap) { treasury += amount - (cap - lpPool); lpPool = cap; } else { lpPool += amount; }`, or (b) explicitly document and"

    _PRECONDITIONS = [{'contract.has_state_var_matching': 'lpPoolCap|poolCap|depositCap|cap|maxDeposit|maxTotalAssets'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(settle|resolve|distribute|accrue|applyProfits|bookWinnings|addRewards|updatePool|_bookWin|recordWin|onGameEnd|finalizeRound|_recordWinnings|settleRound|awardRewards)\\w*'}, {'function.body_contains_regex': {'regex': '(lpPool|lpPoolBalance|poolBalance|totalAssets|totalDeposits)\\s*(\\+=|=\\s*[^;]+\\+)\\s*'}}, {'function.body_not_contains_regex': '<=\\s*(lpPoolCap|poolCap|depositCap|cap|maxDeposit|maxTotalAssets)|>\\s*(lpPoolCap|poolCap|depositCap|cap|maxDeposit|maxTotalAssets)|_overflowToTreasury|if\\s*\\([^)]*>\\s*(lpPoolCap|poolCap|cap)[^)]*\\)'}, {'contract.source_matches_regex': '(lpPoolCap|poolCap|depositCap|cap|maxDeposit|maxTotalAssets)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — cap-enforced-at-entry-not-settlement: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
