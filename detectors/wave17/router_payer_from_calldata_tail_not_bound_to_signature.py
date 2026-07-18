"""
router-payer-from-calldata-tail-not-bound-to-signature — generated from reference/patterns.dsl/router-payer-from-calldata-tail-not-bound-to-signature.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py router-payer-from-calldata-tail-not-bound-to-signature.yaml
Source: defimon-2026-04/uniswapv4-router04-42K
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RouterPayerFromCalldataTailNotBoundToSignature(AbstractDetector):
    ARGUMENT = "router-payer-from-calldata-tail-not-bound-to-signature"
    HELP = "Router executes actions decoded from a `bytes` params blob and reads a `payer/from/sender` field out of that blob, then forwards it into transferFrom — without binding the payer to msg.sender or to a signed payload. Anyone with prior router approvals is at risk."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/router-payer-from-calldata-tail-not-bound-to-signature.yaml"
    WIKI_TITLE = "Router action decodes payer from untrusted bytes; transferFrom uses it without signature binding"
    WIKI_DESCRIPTION = "Universal-router-style contracts decode a series of actions from a single `bytes calldata` blob. One action variant carries a `payer` address that the router uses as the `from` argument of an ERC20 transferFrom (or Permit2 transferFrom) to fund the swap. If the outer function does not assert that the decoded payer equals msg.sender, and there is no EIP-712 / Permit2 signature whose hashed payload "
    WIKI_EXPLOIT_SCENARIO = "April 2026, UniswapV4Router04: 42,607 USDC drained. Attacker calls `execute(commands, inputs)` where one of the inputs is an `action = SETTLE` whose decoded SettleParams contain `payer = 0x65A8...675` (the victim, who had approved Router04 for USDC). The router calls `permit2.transferFrom(payer, address(this), 42607e6, USDC)` — Permit2 still honors a long-lived approval — pulls the funds, then imm"
    WIKI_RECOMMENDATION = "Either (a) refuse to honor a `payer != msg.sender` action unless the call is wrapped in a Permit2 signed permit-and-transfer that the user explicitly co-signed for THIS router invocation, OR (b) require the action blob be EIP-712-signed by the payer with a domain separator scoped to (router, chainId"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(Router|Aggregat|Swap|Action|Universal|V4Router|V3Router|Plan|Execut)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(execute|swap|swapExactInput|swapExactOutput|run|executeActions|executePlan|executeBatch|multicall)[A-Z_]?\\w*$'}, {'function.body_contains_regex': 'abi\\.decode\\s*\\([^)]*params|abi\\.decode\\s*\\([^)]*data|abi\\.decode\\s*\\([^)]*actionData|_decodeAction|_parseActions'}, {'function.body_contains_regex': '(payer|sender|from|fromAddress|authorizedSender|tokenOwner|spender)\\s*[,)]\\s*=|\\.payer|\\.sender|\\.from\\s*[,;]'}, {'function.body_contains_regex': 'transferFrom\\s*\\([^)]*(payer|sender|from|fromAddress|authorizedSender|tokenOwner)|safeTransferFrom\\s*\\([^)]*(payer|sender|from|authorizedSender|tokenOwner)|permitTransferFrom\\s*\\([^)]*(payer|sender|from|authorizedSender|tokenOwner)'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*(p\\.payer|p\\.from|p\\.sender|payer|from|sender|authorizedSender|tokenOwner)\\s*==\\s*(msg\\.sender|_msgSender\\s*\\(\\s*\\))|permitTransferFrom\\s*\\(|\\.permit\\s*\\(|isValidSignature\\s*\\('}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — router-payer-from-calldata-tail-not-bound-to-signature: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
