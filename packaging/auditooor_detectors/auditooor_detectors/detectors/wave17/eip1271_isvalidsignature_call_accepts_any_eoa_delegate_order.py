"""
eip1271-isvalidsignature-call-accepts-any-eoa-delegate-order — generated from reference/patterns.dsl/eip1271-isvalidsignature-call-accepts-any-eoa-delegate-order.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py eip1271-isvalidsignature-call-accepts-any-eoa-delegate-order.yaml
Source: polymarket-draft-9
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Eip1271IsvalidsignatureCallAcceptsAnyEoaDelegateOrder(AbstractDetector):
    ARGUMENT = "eip1271-isvalidsignature-call-accepts-any-eoa-delegate-order"
    HELP = "Order-matching entrypoint authenticates a maker-supplied address through EIP-1271 isValidSignature with no defence against EIP-7702-delegated EOAs. An attacker can install a permissive 1271 delegate on their own EOA via a 7702 set-code authorization (or victim's, if pre-signed authorization leaks), "
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/eip1271-isvalidsignature-call-accepts-any-eoa-delegate-order.yaml"
    WIKI_TITLE = "EIP-1271 isValidSignature on maker accepts forged orders from 7702-delegated EOAs"
    WIKI_DESCRIPTION = "CTFExchange-style matching contracts dispatch order signatures by signature-type tag: EOA → ECDSA recover; POLY_1271 → IERC1271(maker).isValidSignature(hash, sig) and accept the order if the magic value 0x1626ba7e is returned. Pre-Pectra this was safe-ish: only contract makers had isValidSignature available, and the maker had to deploy a real 1271 wallet. Post-Pectra (EIP-7702) any EOA can install"
    WIKI_EXPLOIT_SCENARIO = "Polymarket CTFExchange `_verifyPoly1271Signature(signer, maker, hash, sig)` returns true when `signer == maker && maker.code.length > 0 && SignatureCheckerLib.isValidSignatureNow(maker, hash, sig)`. Attacker controls EOA `A`, deploys delegate `D` whose `isValidSignature` returns 0x1626ba7e unconditionally, sends a 7702 type-4 tx setting `A`'s code pointer to `D`. Attacker now submits an order with"
    WIKI_RECOMMENDATION = "Either (a) maintain an explicit allowlist of permitted 1271 validator contracts and require `maker ∈ allowlist` before routing to isValidSignature, or (b) reject the 1271 path entirely for addresses whose runtime code begins with the EIP-7702 prefix `0xef0100`. Reading the first 3 bytes of `maker.co"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(Exchange|Order|Trade|Clob|Book|Auction|Matcher)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '^(fillOrder|matchOrders|executeOrder|_fillOrder|_processOrder|validateOrder|_validateOrder|verifyPoly1271Signature|_verifyPoly1271Signature|_isValidSignature|validateOrderSignature|_validateOrderSignature)$'}, {'function.body_contains_regex': '(?i)(IERC1271\\s*\\(|\\.isValidSignature\\s*\\(|SignatureChecker(Lib)?\\.\\s*isValidSignature(Now)?\\s*\\(|0x1626ba7e)'}, {'function.body_not_contains_regex': '(?i)(eoa_only|no_7702|isContract\\(maker\\)\\s*==\\s*false|assembly\\s*\\{\\s*extcodesize|allowed1271|whitelisted1271|trusted1271Validator|allowedDelegate|isAllowedDelegate)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — eip1271-isvalidsignature-call-accepts-any-eoa-delegate-order: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
