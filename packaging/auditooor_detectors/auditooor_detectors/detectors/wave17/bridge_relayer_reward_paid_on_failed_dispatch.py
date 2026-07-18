"""
bridge-relayer-reward-paid-on-failed-dispatch — generated from reference/patterns.dsl/bridge-relayer-reward-paid-on-failed-dispatch.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bridge-relayer-reward-paid-on-failed-dispatch.yaml
Source: snowbridge-r109-source-mine-gateway-v1-submitV1
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BridgeRelayerRewardPaidOnFailedDispatch(AbstractDetector):
    ARGUMENT = "bridge-relayer-reward-paid-on-failed-dispatch"
    HELP = "Inbound-message dispatcher pays the relayer's gas refund / bounty even when the inner try/catch caught a handler failure. Relayers can profit from delivering messages that revert."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bridge-relayer-reward-paid-on-failed-dispatch.yaml"
    WIKI_TITLE = "Inbound dispatcher pays relayer reward unconditionally on handler revert"
    WIKI_DESCRIPTION = "A cross-chain inbound-queue dispatcher follows a common pattern: it caps gas via `try { handler{gas: maxDispatchGas}() } catch { success = false; }`, then refunds the relayer based on `(startGas - gasleft()) * tx.gasprice` plus a bounty. The refund/bounty payment is NOT gated on the `success` flag; it runs regardless of handler outcome. The intent is to compensate relayers for delivering ANY valid"
    WIKI_EXPLOIT_SCENARIO = "Snowbridge `Gateway.submitV1`: after the try/catch dispatcher loop sets `success = false` on a reverting handler, the function unconditionally executes `payable(msg.sender).safeNativeTransfer(amount)` where amount = gasUsed*gasPrice + reward. Attacker controls a Polkadot account; emits an outbound MintForeignToken message for a token that the Ethereum gateway has not yet registered, knowing the ha"
    WIKI_RECOMMENDATION = "Gate the relayer payout on `success`. If `success` is false, either (a) refund only the gas portion (not the bounty) to discourage failure-spam, or (b) refund nothing and add a separate retryable-message mechanism so relayers re-attempt the same nonce. Document explicitly which model the bridge uses"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(submitV[12]|inboundMessage|dispatch|relayer|reward|refund)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': 'try\\s+\\w+\\s*[\\(\\.][\\s\\S]{0,2000}?catch\\s*(?:\\([^)]*\\))?\\s*\\{\\s*success\\s*=\\s*false'}, {'function.body_contains_regex': '(?:safeNativeTransfer|\\.call\\s*\\{\\s*value\\s*:|\\.transfer\\s*\\(|payable\\s*\\(\\s*msg\\.sender\\s*\\))'}, {'function.body_not_contains_regex': 'if\\s*\\(\\s*success\\s*\\)\\s*\\{[\\s\\S]{0,200}?(?:safeNativeTransfer|\\.call|\\.transfer|payable\\s*\\()'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*success\\s*[,)]'}, {'function.body_contains_regex': 'reward|refund|gasUsed|tx\\.gasprice'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — bridge-relayer-reward-paid-on-failed-dispatch: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
