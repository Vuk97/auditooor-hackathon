"""
eip7702-eoa-check-via-codelen — generated from reference/patterns.dsl/eip7702-eoa-check-via-codelen.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py eip7702-eoa-check-via-codelen.yaml
Source: auditooor-R73-eip7702-class
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Eip7702EoaCheckViaCodelen(AbstractDetector):
    ARGUMENT = "eip7702-eoa-check-via-codelen"
    HELP = "EOA check via code.length==0 / isContract fails under EIP-7702 — 7702-delegated EOAs have code and will be misclassified as contracts (blocking legit users) or vice versa for address(this)-style checks."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/eip7702-eoa-check-via-codelen.yaml"
    WIKI_TITLE = "EOA detection via code.length == 0 breaks under EIP-7702 delegated accounts"
    WIKI_DESCRIPTION = "EIP-7702 (Pectra) lets an EOA set a persistent code pointer to a contract via a type-4 authorization. After delegation, the EOA's `code.length` returns the 23-byte `0xef0100 || address` stub — non-zero. Any contract using `account.code.length == 0` or `extcodesize == 0` to distinguish 'real humans' from 'contracts' will now treat 7702 delegates as contracts: they'll be locked out of airdrops/claim"
    WIKI_EXPLOIT_SCENARIO = "Airdrop contract has `require(claimer.code.length == 0, 'contracts not allowed')`. A legitimate user whose wallet has opted into 7702 for a smart-account delegate is permanently blocked from claiming. Or conversely: a lending protocol skips the reentrancy guard when `tx.origin == msg.sender`, trusting that the caller is a pure EOA; an attacker with 7702 delegation runs multi-step reentrant code in"
    WIKI_RECOMMENDATION = "Do not use `code.length == 0`, `extcodesize == 0`, or `tx.origin == msg.sender` to infer 'safe/human EOA'. If the intent is re-entrancy protection, use a real nonReentrant modifier. If the intent is anti-airdrop-farming, use a signature-based proof of eligibility, not account-type detection. For con"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)EOA|isContract|isEOA|accountType|extCodeSize|\\.code\\.length'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.body_contains_regex': '(?:tx\\.origin\\s*==\\s*msg\\.sender|extcodesize\\s*\\(\\s*\\w+\\s*\\)\\s*==\\s*0|\\.code\\.length\\s*==\\s*0|isContract\\s*\\(\\s*\\w+\\s*\\)\\s*==\\s*false|!isContract\\s*\\(\\s*\\w+\\s*\\))'}, {'function.body_contains_regex': '(?i)(transfer|deposit|claim|mint|airdrop|reward|redeem|swap|borrow)'}, {'function.body_not_contains_regex': '(?i)7702|authorizationList|delegated|\\.delegation\\s*\\(|isDelegated|AUTH_MAGIC'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — eip7702-eoa-check-via-codelen: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
