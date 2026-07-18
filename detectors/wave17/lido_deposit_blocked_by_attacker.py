"""
lido-deposit-blocked-by-attacker — generated from reference/patterns.dsl/lido-deposit-blocked-by-attacker.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py lido-deposit-blocked-by-attacker.yaml
Source: solodit-cluster-C0079
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LidoDepositBlockedByAttacker(AbstractDetector):
    ARGUMENT = "lido-deposit-blocked-by-attacker"
    HELP = "Contract keeps a mirror of Lido stETH/ETH state and gates deposits/redemptions on it. An attacker donates ETH or stETH directly to Lido or to the contract to desync the mirror and block user flows."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/lido-deposit-blocked-by-attacker.yaml"
    WIKI_TITLE = "Lido deposit/redeem can be blocked by attacker desyncing a locally-mirrored balance"
    WIKI_DESCRIPTION = "Integrations that track Lido's stETH or ETH balance in a local state variable (lidoLocked, lidoBalance, lidoMirror, stETHLocked) and gate deposit/redeem/withdraw math on that mirror are vulnerable when the mirror is never reconciled against the true on-chain balance. A third party can push the real balance above or below the mirror with a bare `selfdestruct`, a direct `stETH.transfer`, or an unboo"
    WIKI_EXPLOIT_SCENARIO = "A liquid-restaking adapter tracks `lidoLockedETH` as the sum of user deposits. The `deposit()` function reads `lidoLockedETH`, compares it to Lido's reported balance, and reverts on mismatch to prevent accounting drift. An attacker sends 1 wei of stETH directly to Lido on the adapter's behalf (or self-destructs a contract with a dust balance into the adapter). The reported balance now exceeds `lid"
    WIKI_RECOMMENDATION = "Never gate value-movement on a naive mirror-vs-live comparison. Either (1) make every mirror-reading function first call a `_syncLidoBalance` / `snapshotBalance` helper that absorbs unsolicited donations into a `donationBuffer` and updates the mirror to match live state, or (2) track only the shares"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'lidoLocked|lidoBalance|lidoMirror|stETHLocked'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'deposit|redeem|withdraw|_redeemLido|_syncLido'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': 'lidoLocked|lidoBalance|lidoMirror|stETH\\.balanceOf|IStETH\\.balanceOf'}, {'function.body_not_contains_regex': '_reconcile|updateMirror|syncBalance|_syncLidoBalance|snapshotBalance'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — lido-deposit-blocked-by-attacker: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
