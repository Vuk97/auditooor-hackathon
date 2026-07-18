"""
rg-01-native-reward-stale-totalassets-cancel-lock — generated from reference/patterns.dsl/rg-01-native-reward-stale-totalassets-cancel-lock.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py rg-01-native-reward-stale-totalassets-cancel-lock.yaml
Source: reserve-governor/RG-01
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Rg01NativeRewardStaleTotalassetsCancelLock(AbstractDetector):
    ARGUMENT = "rg-01-native-reward-stale-totalassets-cancel-lock"
    HELP = "Cancel-lock redeposit mints vault shares against stale totalAssets before native reward snapshot, letting a locked unstaker capture rewards funded while they had no shares."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/rg-01-native-reward-stale-totalassets-cancel-lock.yaml"
    WIKI_TITLE = "Cancel-lock redeposit prices shares before native reward snapshot"
    WIKI_DESCRIPTION = "A vault's share mint path prices new shares from totalAssets, but totalAssets excludes newly transferred native asset rewards until a later reward snapshot/checkpoint updates cached accounting. If an unstaking manager lets a previously redeemed user cancel a lock and redeposit through that mint path before the snapshot, the user can mint shares at the stale pre-reward price and dilute active stake"
    WIKI_EXPLOIT_SCENARIO = "Alice and Bob stake equally. Bob redeems into an unstaking lock and has zero vault shares. Native asset rewards are funded directly to the vault. Before a reward snapshot runs, Bob calls cancelLock, which redeposits the locked amount through deposit. Because share conversion still sees the pre-reward totalAssets value, Bob mints underpriced shares and captures part of the rewards funded while only"
    WIKI_RECOMMENDATION = "Snapshot/account native rewards before any share conversion reachable from deposit, mint, cancelLock, or similar re-entry paths; alternatively make totalAssets include the live asset balance used for reward funding, or prevent cancelLock from redepositing until pending native rewards are checkpointe"

    _PRECONDITIONS = []
    _MATCH = []

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
                info = [f, f" — rg-01-native-reward-stale-totalassets-cancel-lock: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
