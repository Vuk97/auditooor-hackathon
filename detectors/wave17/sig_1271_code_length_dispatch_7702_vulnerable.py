"""
sig-1271-code-length-dispatch-7702-vulnerable — generated from reference/patterns.dsl/sig-1271-code-length-dispatch-7702-vulnerable.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py sig-1271-code-length-dispatch-7702-vulnerable.yaml
Source: auditooor-R77-polymarket-Signatures-validateOrderSignature
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Sig1271CodeLengthDispatch7702Vulnerable(AbstractDetector):
    ARGUMENT = "sig-1271-code-length-dispatch-7702-vulnerable"
    HELP = "Signature verifier dispatches to ERC-1271 based solely on `code.length > 0`. Post-EIP-7702, any delegated EOA has code, so this check routes EOA signatures through a (possibly permissive) 1271 delegate. Signatures can be forged against 7702-delegated victims."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/sig-1271-code-length-dispatch-7702-vulnerable.yaml"
    WIKI_TITLE = "ERC-1271 dispatch via code.length is bypassed by EIP-7702 delegation"
    WIKI_DESCRIPTION = "Pre-Pectra, `maker.code.length > 0` reliably distinguished smart contract wallets from EOAs. Post-Pectra (EIP-7702), EOAs that opt into delegation have a 23-byte code stub (`0xef0100 || targetAddr`) — the code-length check now misclassifies them as contracts. If the delegate implements ERC-1271 permissively (common in 'smart-EOA' wallet kits that accept any well-formed hash), anyone can forge orde"
    WIKI_EXPLOIT_SCENARIO = "Victim EOA has approved the Exchange for 1000 USDC and 7702-delegated to 'AcceptAllSignatures' smart-wallet code. Attacker crafts order `{maker: victim, sell 1000 USDC}` with arbitrary sig bytes. Exchange sees `victim.code.length > 0` → calls `victim.isValidSignature(hash, sig)` → delegate returns magic value → order validates. Victim's USDC drains."
    WIKI_RECOMMENDATION = "Use explicit opt-in registration for 1271 signers: only dispatch to 1271 when `polyOptedInto1271[maker] == true`. Otherwise use ECDSA recover — which works correctly for both plain EOAs and 7702-delegated EOAs. Alternative: detect the 0xef0100 prefix in the code to identify 7702-delegated accounts a"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)IERC1271|isValidSignature|POLY_1271'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.name_matches': '(?i)_?validateSig|_?verifySig|_?recoverSigner|_?isValid'}, {'function.body_contains_regex': '(?i)\\.code\\.length\\s*>\\s*0|extcodesize\\s*\\(\\s*\\w+\\s*\\)\\s*>\\s*0'}, {'function.body_contains_regex': '(?i)isValidSignature\\s*\\(|1626ba7e'}, {'function.body_not_contains_regex': '(?i)(0xef0100|7702|authorizationList|delegated|isDelegated|opted\\s*in|whitelist1271)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — sig-1271-code-length-dispatch-7702-vulnerable: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
