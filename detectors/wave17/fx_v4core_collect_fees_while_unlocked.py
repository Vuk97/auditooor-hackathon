"""
fx-v4core-collect-fees-while-unlocked — generated from reference/patterns.dsl/fx-v4core-collect-fees-while-unlocked.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-v4core-collect-fees-while-unlocked.yaml
Source: github:Uniswap/v4-core@4dc48bb
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxV4coreCollectFeesWhileUnlocked(AbstractDetector):
    ARGUMENT = "fx-v4core-collect-fees-while-unlocked"
    HELP = "collectProtocolFees() does not revert when called during an active unlock session. Token transfers during an unlock window corrupt the sync/settle delta accounting, potentially enabling double-spending of protocol fees."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-v4core-collect-fees-while-unlocked.yaml"
    WIKI_TITLE = "collectProtocolFees callable mid-unlock — fee collection disrupts sync/settle accounting"
    WIKI_DESCRIPTION = "Pool managers that use a transient-storage sync/settle payment cycle must prevent any token transfer out of the contract while an unlock session is active. If collectProtocolFees() can be called by the fee controller mid-unlock, the transfer reduces the pool's actual token balance below what was synced, causing settle() to credit callers for tokens that were actually taken by the fee controller."
    WIKI_EXPLOIT_SCENARIO = "Uniswap v4 (2023): fee controller calls collectProtocolFees(USDC, 1000) during an attacker's unlock callback. Pool's USDC balance drops by 1000. Attacker's settle() now calculates paid = newBalance - reservesBefore where reservesBefore included the 1000, enabling theft."
    WIKI_RECOMMENDATION = "Add `if (_isUnlocked()) revert ContractUnlocked()` at the start of collectProtocolFees(). Guard any external token transfer function that is not part of the sync/settle flow with a locked-state check."

    _PRECONDITIONS = [{'contract.has_function_matching': '^(collectProtocolFees|collectFees|withdrawFees)$'}, {'contract.has_function_matching': '^unlock$'}, {'contract.source_matches_regex': '(PoolManager|IPoolManager|V4PoolManager|ProtocolFees|sync\\s*\\(|settle\\s*\\(|unlock\\s*\\(|transient|TLOAD|tstore|Lock\\.isUnlocked|CurrencyDelta)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(collectProtocolFees|collectFees|withdrawFees|sweepFees|harvestProtocolFees)$'}, {'function.has_external_call': True}, {'function.body_contains_regex': 'transfer|protocolFee|accrued'}, {'function.body_not_contains_regex': 'isUnlocked|onlyLocked|ContractUnlocked|!.*unlock|unlocked.*revert'}, {'function.not_source_matches_regex': '(?i)(view\\s+returns|pure\\s+returns|internal\\s+view|modifier\\s+onlyLocked|modifier\\s+whenLocked|Lock\\.isUnlocked\\s*\\(\\s*\\)\\s*\\)\\s*revert|if\\s*\\(\\s*Lock\\.isUnlocked|require\\s*\\(\\s*!\\s*Lock\\.isUnlocked|tload\\s*\\(\\s*IS_UNLOCKED|pendingFees\\s*\\[)'}]

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
                info = [f, f" — fx-v4core-collect-fees-while-unlocked: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
