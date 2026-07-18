"""
glider-eoa-check-via-codesize-bypassable — generated from reference/patterns.dsl/glider-eoa-check-via-codesize-bypassable.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-eoa-check-via-codesize-bypassable.yaml
Source: hexens-glider/eoa-restricted-modifiers-that-checks-the-bytecode
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderEoaCheckViaCodesizeBypassable(AbstractDetector):
    ARGUMENT = "glider-eoa-check-via-codesize-bypassable"
    HELP = "EOA-only guard uses `extcodesize(msg.sender) == 0` or `msg.sender.code.length == 0`. A contract's code is not deployed during its constructor, so any contract can pass the check by calling from a constructor — bypassing flashloan-safety / per-wallet-mint / bot-prevention logic."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-eoa-check-via-codesize-bypassable.yaml"
    WIKI_TITLE = "EOA gate bypassable via constructor codesize trick"
    WIKI_DESCRIPTION = "Functions that intend to admit only externally-owned accounts routinely check `extcodesize(msg.sender) == 0`. This is unsound: during a contract's constructor execution, the contract's code is not yet stored at its address. A malicious contract can therefore masquerade as an EOA by performing the restricted call from its constructor. If EOA-only access is strictly required, use `require(tx.origin "
    WIKI_EXPLOIT_SCENARIO = "An NFT mint caps at 1 per EOA via `require(msg.sender.code.length == 0)`. Attacker writes a factory contract whose constructor calls `nft.mint()`. Deploys N factories in one transaction → mints N NFTs under distinct addresses, each of which passes the codesize check at the moment of minting because their own bytecode has not yet been committed. Same trick defeats bot protections and flashloan-borr"
    WIKI_RECOMMENDATION = "If EOA-only access is a hard requirement, use `require(tx.origin == msg.sender, \"only EOA\")`. Otherwise drop the check — contract callers are usually legitimate (smart wallets, aggregators) and the constructor bypass makes the codesize guard security theatre."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'extcodesize|\\.code\\.length'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': 'extcodesize\\s*\\(\\s*msg\\.sender|msg\\.sender\\.code\\.length|address\\s*\\(\\s*msg\\.sender\\s*\\)\\.code\\.length'}, {'function.body_not_contains_regex': 'tx\\.origin\\s*==\\s*msg\\.sender'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-eoa-check-via-codesize-bypassable: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
