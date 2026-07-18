"""
bridge-state-root-proof-payout-unbound-to-export — generated from reference/patterns.dsl/bridge-state-root-proof-payout-unbound-to-export.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bridge-state-root-proof-payout-unbound-to-export.yaml
Source: Incident HACKERMAN_V3 Lane I4 - VerusCoin Ethereum BTC-bridge 2026-05-17 (reported_unverified); analogue Nomad 2022-08, MAP/Butter 2026-05
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BridgeStateRootProofPayoutUnboundToExport(AbstractDetector):
    ARGUMENT = "bridge-state-root-proof-payout-unbound-to-export"
    HELP = "Bridge payout releases custody after a state-root proof without consuming a unique source export/txid"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bridge-state-root-proof-payout-unbound-to-export.yaml"
    WIKI_TITLE = "Bridge state-root proof payout not bound to a unique consumed source export"
    WIKI_DESCRIPTION = "A cross-chain bridge dispatcher releases custody (token transfer or mint) on a payout/disburse/settle path that verifies payload components against a state-root proof but does not read or write any processed-txid / consumed-export ledger. Verifying that attacker-authored components are well-formed under a state root proves component validity, not that the payout corresponds to a real, unspent, aut"
    WIKI_EXPLOIT_SCENARIO = "Anchor incident (reported_unverified): the 2026-05-17 VerusCoin Ethereum bridge paid ETH/tBTC/USDC from custody after a proof path accepted payload components against a state-root path; the payout was not bound to a unique unspent authorized export/txid and the settlement path did not consult _processedTxids. An attacker authors payload components that satisfy the state-root proof, reaches a payou"
    WIKI_RECOMMENDATION = "Bind the disbursed token, recipient, amount, source chain, and a unique source-export/txid identifier into the exact verified bridge commitment before any custody release or mint. Consume the unique source export/txid into a persistent processed-ledger (_processedTxids) and check it for prior consum"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(bridge|crosschain|cross-chain|dispatcher|export|stateRoot|merkleRoot|proof)'}]
    _MATCH = [{'function.name_matches': '(?i).*(payout|payOut|disburse|release|settle|withdraw|claimExport|processExport|finalize).*'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.is_mutating': True}, {'function.body_contains_regex': '(?i)(\\.transfer\\s*\\(|\\.call\\{value|safeTransfer|_mint\\s*\\(|safeTransferFrom)'}, {'function.body_not_contains_regex': '(?i)(_?processed[A-Za-z0-9_]*[Tt]xid|_?consumed[A-Za-z0-9_]*[Ee]xport|_?spent[A-Za-z0-9_]*(Export|Txid|Output)|markSpent|markConsumed|consumeExport|isProcessed|alreadyProcessed)'}]

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
                info = [f, f" — bridge-state-root-proof-payout-unbound-to-export: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
