"""
fx-gmx-event-wrong-signature — generated from reference/patterns.dsl/fx-gmx-event-wrong-signature.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-gmx-event-wrong-signature.yaml
Source: github:GMX-io/gmx-contracts@276a083
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxGmxEventWrongSignature(AbstractDetector):
    ARGUMENT = "fx-gmx-event-wrong-signature"
    HELP = "signalSetMinter() emits SignalSetHandler instead of the semantically correct SignalSetMinter event. Off-chain monitors and indexers filtering for minter-specific events will miss these actions, enabling silent minter privilege changes."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-gmx-event-wrong-signature.yaml"
    WIKI_TITLE = "Timelock signalSetMinter emits wrong event type — off-chain monitors miss minter privilege changes"
    WIKI_DESCRIPTION = "Timelock signal functions that emit a generic event type instead of a dedicated event make off-chain monitoring ambiguous. When signalSetMinter emits SignalSetHandler, any indexer or alert system watching specifically for minter changes will miss these actions, reducing the security of the timelock transparency guarantee."
    WIKI_EXPLOIT_SCENARIO = "GMX Timelock (2024): signalSetMinter(_target, _minter, _isActive) emits SignalSetHandler instead of SignalSetMinter. Security monitoring tools watching for SignalSetMinter events never fire, allowing minter privilege changes to be added to the timelock queue without triggering security alerts."
    WIKI_RECOMMENDATION = "Define a dedicated event for each signal type and emit it in the corresponding signal function: `event SignalSetMinter(address target, address minter, bool isActive, bytes32 action)`. Never reuse events from other signal functions."

    _PRECONDITIONS = [{'contract.has_function_matching': '^signal'}, {'contract.source_matches_regex': '(Timelock|TimelockController|GovTimelock|Governance|Admin|Multisig|GMX|signalSetMinter|signalSetHandler|signalPendingAction)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(signalSetMinter|signalSetHandler|signalApprove|signalMint|signalSetGov|signalSetAdmin|signalSetPriceFeed|signalVaultSetTokenConfig|signalRedeem|signalPendingAction|signalSetKeeper)$'}, {'function.body_contains_regex': 'emit\\s+Signal\\w+\\('}, {'function.body_contains_regex': 'action\\s*=\\s*keccak256|_setPendingAction|pendingActions\\['}, {'function.not_source_matches_regex': '(?i)(view\\s+returns|pure\\s+returns|internal\\s+function\\s+_signal|function\\s+_signal\\s*\\(|emit\\s+SignalSetMinter\\s*\\([^;]*_minter|emit\\s+Signal\\w*\\s*\\(\\s*action)'}]

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
                info = [f, f" — fx-gmx-event-wrong-signature: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
