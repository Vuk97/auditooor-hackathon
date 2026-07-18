"""
ccip-receiver-and-chain-unvalidated — generated from reference/patterns.dsl/ccip-receiver-and-chain-unvalidated.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ccip-receiver-and-chain-unvalidated.yaml
Source: solodit/sherlock/winnables-H1-38402
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CcipReceiverAndChainUnvalidated(AbstractDetector):
    ARGUMENT = "ccip-receiver-and-chain-unvalidated"
    HELP = "Cross-chain propagation accepts destination address and chain id as untrusted parameters AND marks one-shot state as propagated. A griefer picks a wrong destination, the message vanishes, and the locked prize can never be retried."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ccip-receiver-and-chain-unvalidated.yaml"
    WIKI_TITLE = "Cross-chain propagator accepts unvalidated destination AND burns retry state"
    WIKI_DESCRIPTION = "The contract exposes a permissionless function that fans out a finalization message (raffle winner, settlement, refund) across chains via CCIP / LayerZero / Hyperlane. Both the destination contract address and the chain selector are supplied by the caller and never checked against an expected constant or an allowlist. The function additionally flips a one-shot flag (`propagated = true`, or clears "
    WIKI_EXPLOIT_SCENARIO = "WinnablesTicketManager.propagateRaffleWinner is `external`. User calls it as `propagateRaffleWinner(address(0xDEAD), 9846, raffleId)`. CCIP router accepts the call (9846 is valid), the message is dispatched to 0xDEAD on that chain, and the source contract sets `raffle.status = PROPAGATED`. The winner can no longer trigger a real propagation and the prize tokens in WinnablesPrizeManager on the dest"
    WIKI_RECOMMENDATION = "Hard-code or allowlist the (destination-address, chain-selector) pair per resource. Either read it from a trusted registry keyed by raffleId, or enforce `require(prizeManager == expectedPrizeManager[chainSelector])`. Pair that with a retry mechanism that lets the rightful recipient re-propagate if t"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.source_matches_regex': 'ccipSend|dispatch\\s*\\(|_lzSend|sendMessage|mailbox'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_param_of_type': 'address'}, {'function.has_param_of_type': 'uint'}, {'function.body_contains_regex': 'ccipSend|dispatch\\s*\\(|_lzSend|sendMessage|mailbox'}, {'function.body_contains_regex': '(destinationChainSelector|dstChainId|destinationDomain|chainSelector|chainId)\\s*[,:]'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*(prizeManager|receiver|destination)\\s*==\\s*(expected|trusted|allowlist)|isAllowlisted|allowedDestinations\\[|expectedDestination'}, {'function.body_contains_regex': '(propagated|sent|delivered|claimed|processed|winnerPropagated)\\s*=\\s*true|processed\\s*\\[.*\\]\\s*=\\s*true'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — ccip-receiver-and-chain-unvalidated: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
