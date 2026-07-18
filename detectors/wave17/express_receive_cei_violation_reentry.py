"""
express-receive-cei-violation-reentry — generated from reference/patterns.dsl/express-receive-cei-violation-reentry.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py express-receive-cei-violation-reentry.yaml
Source: solodit/c4/axelar-H01-28759
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ExpressReceiveCeiViolationReentry(AbstractDetector):
    ARGUMENT = "express-receive-cei-violation-reentry"
    HELP = "Express / pre-fill flow transfers tokens and calls user code BEFORE marking the commandId paid. Malicious destination reenters gateway.execute and triggers the normal transfer path, collecting both the express transfer and the canonical transfer."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/express-receive-cei-violation-reentry.yaml"
    WIKI_TITLE = "Express / pre-fill function sets 'paid' flag after external call — reentrant double-receive"
    WIKI_DESCRIPTION = "Bridge / cross-chain 'express' paths let a relayer front-fund token deliveries ahead of the canonical settlement. The function transfers tokens to the recipient, calls into the recipient's `executeWith*` handler, and then records that the commandId was express-paid. Because the recipient-call happens before the 'paid' flag is set, a malicious recipient can reenter: submit the canonical message to "
    WIKI_EXPLOIT_SCENARIO = "Attacker sends a large cross-chain transfer with a malicious destination contract. Relayer front-funds via `expressReceiveTokenWithData(..., recipient, amount, data, commandId)`. Relayer's tokens go to recipient. Recipient's `expressExecuteWithInterchainToken` calls `gateway.approveContractCall(params, commandId)` and then `interchainTokenService.execute(commandId, ...)`. Because `_setExpressRecei"
    WIKI_RECOMMENDATION = "Strict CEI: call `_setExpressReceiveTokenWithData(...)` BEFORE any external call into recipient code. Additionally add `nonReentrant` to `expressReceive*` and to the gateway's `execute` path, or use a two-phase approval where the relayer first commits and only later releases funds after the commandI"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(InterchainTokenService|AxelarGateway|ExpressReceive|BridgeReceiver|RelayerBridge|CrossChainExecutor|expressExecute|expressReceiveToken|preFillOrder)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(expressReceiveToken|expressReceiveTokenWithData|preFill|preFillOrder|fillBefore|flushPending|expressExecute|expressExecuteWithInterchainToken)\\w*$'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.body_contains_regex': 'safeTransferFrom\\s*\\(|safeTransfer\\s*\\(|IERC20\\s*\\([^)]*\\)\\.transfer'}, {'function.body_contains_regex': '_expressExecute|executeWith\\w+|callWithInterchainToken|onReceive|onPreFill'}, {'function.body_ordered_regex': {'first': 'safeTransferFrom|safeTransfer|_expressExecute|executeWith|callWithInterchain', 'second': '(_set\\w*Receive|processed\\[.*\\]\\s*=\\s*true|expressPaid\\[|commands\\[[^\\]]*\\]\\s*=\\s*true|usedBy\\[)'}}, {'function.modifiers_not_matching': 'nonReentrant'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)(view\\s+returns|pure\\s+returns|_status\\s*==\\s*_NOT_ENTERED|_status\\s*=\\s*_ENTERED|setExpressReceive\\w*\\s*\\([^)]*\\)\\s*internal|require\\s*\\(\\s*!processed\\[|require\\s*\\(\\s*!expressPaid\\[|if\\s*\\(\\s*expressPaid\\[|nonReentrantBefore|super\\.expressReceive)'}]

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
                info = [f, f" — express-receive-cei-violation-reentry: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
