"""
bridge-dispatcher-delegatecall-skips-processed-txid-gate - generated from reference/patterns.dsl/bridge-dispatcher-delegatecall-skips-processed-txid-gate.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bridge-dispatcher-delegatecall-skips-processed-txid-gate.yaml
Source: Incident HACKERMAN_V3 Lane I4 - VerusCoin Ethereum BTC-bridge 2026-05-17 (reported_unverified); sub-gap B - dispatcher reaches payout via delegatecall / dispatch table where the dispatched target does not read/write the processed-txid ledger
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BridgeDispatcherDelegatecallSkipsProcessedTxidGate(AbstractDetector):
    ARGUMENT = "bridge-dispatcher-delegatecall-skips-processed-txid-gate"
    HELP = "A bridge dispatcher reaches a value transfer via delegatecall or a dispatch table where the dispatched target does not read/write a processed-txid / consumed-export ledger, allowing replay or synthetic-component drains"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bridge-dispatcher-delegatecall-skips-processed-txid-gate.yaml"
    WIKI_TITLE = "Bridge dispatcher reaches payout via delegatecall without consulting processed-txid ledger"
    WIKI_DESCRIPTION = "A bridge dispatcher contract routes inbound cross-chain messages to a payout target via delegatecall or a low-level call-based dispatch table. The dispatched target performs a token transfer or mint but does not read or write a processed-txid / consumed-export ledger. Because the dispatcher delegates execution context and the target lacks the consume-once gate, the bridge has no record that a source export has been drained, enabling replay of the same proof inputs or synthetic inputs across multiple dispatch calls. This is the sub-gap-B axis of the VerusCoin 2026-05-17 incident pattern; it fires when the consume-once gap is introduced by the delegatecall / dispatch hop rather than being absent from the payout function directly."
    WIKI_EXPLOIT_SCENARIO = "An attacker calls the dispatcher with proof inputs for a source export. The dispatcher routes to the payout target via delegatecall. The payout target transfers custody without consulting a processed-txid ledger. The attacker replays the same call; the dispatcher repeats the delegatecall; the target again transfers custody. Custody is drained until empty."
    WIKI_RECOMMENDATION = "Ensure the processed-txid / consumed-export ledger is checked and written at the dispatcher entry point (before the delegatecall) rather than relying solely on the delegated target to enforce it. Alternatively, ensure the dispatched target's storage layout is aligned and actually reads/writes the consume-once ledger. Verify with a fixture that the same proof inputs cannot trigger a second successful payout."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(bridge|crosschain|cross-chain|dispatcher|gateway|router|relay)'}]
    _MATCH = [{'function.name_matches': '(?i).*(dispatch|execute|relay|process|handle|route|forward|invoke).*'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.is_mutating': True}, {'function.body_contains_regex': '(?i)(delegatecall|\\.call\\s*\\(|\\.call\\{|functionDelegateCall|Address\\.functionCall|IDispatch|dispatch\\s*\\(|_dispatch\\s*\\()'}, {'function.body_contains_regex': '(?i)(\\.transfer\\s*\\(|\\.call\\{value|safeTransfer|_mint\\s*\\(|safeTransferFrom|payout|payOut|disburse|releaseFunds)'}, {'function.body_not_contains_regex': '(?i)(_?processed[A-Za-z0-9_]*[Tt]xid|_?consumed[A-Za-z0-9_]*[Ee]xport|_?spent[A-Za-z0-9_]*(Export|Txid|Output)|markSpent|markConsumed|consumeExport|isProcessed|alreadyProcessed)'}]

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
                info = [f, f" - bridge-dispatcher-delegatecall-skips-processed-txid-gate: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
