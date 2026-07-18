"""
r94-loop-upgrade-moved-storage-uninitialised-post-upgrade — generated from reference/patterns.dsl/r94-loop-upgrade-moved-storage-uninitialised-post-upgrade.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-upgrade-moved-storage-uninitialised-post-upgrade.yaml
Source: solodit-53719-sigmaprime-eigenlayer
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopUpgradeMovedStorageUninitialisedPostUpgrade(AbstractDetector):
    ARGUMENT = "r94-loop-upgrade-moved-storage-uninitialised-post-upgrade"
    HELP = "r94-loop-upgrade-moved-storage-uninitialised-post-upgrade"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-upgrade-moved-storage-uninitialised-post-upgrade.yaml"
    WIKI_TITLE = "r94-loop-upgrade-moved-storage-uninitialised-post-upgrade"
    WIKI_DESCRIPTION = "r94-loop-upgrade-moved-storage-uninitialised-post-upgrade"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-upgrade-moved-storage-uninitialised-post-upgrade"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(Upgradeable|Initializable|DelegationManager|EigenLayer|StrategyManager)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(withdraw|completeQueuedWithdrawal|initiateWithdrawal|queueWithdrawal|finalize|executeUpgrade|claim)'}, {'function.source_matches_regex': '(withdrawalDelayBlocks|withdrawalDelay|withdrawDelayBlocks|escapeHatchDelay|pauseDelay|upgradeDelayBlocks)'}, {'function.not_source_matches_regex': '(setWithdrawalDelayBlocks|setWithdrawDelay|updateWithdrawalDelay|setPauseDelay|setEscapeHatchDelay|setUpgradeDelayBlocks)'}]

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
                info = [f, f" — r94-loop-upgrade-moved-storage-uninitialised-post-upgrade: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
