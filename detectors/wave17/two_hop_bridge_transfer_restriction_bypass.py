"""
two-hop-bridge-transfer-restriction-bypass — generated from reference/patterns.dsl/two-hop-bridge-transfer-restriction-bypass.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py two-hop-bridge-transfer-restriction-bypass.yaml
Source: code4arena/slice_ac-THORWallet-H
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class TwoHopBridgeTransferRestrictionBypass(AbstractDetector):
    ARGUMENT = "two-hop-bridge-transfer-restriction-bypass"
    HELP = "Token's local transfer path enforces whitelist/blacklist/lockup but the cross-chain credit (lzReceive / _credit) path does not. Bridging out and back to a fresh address washes the restriction."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/two-hop-bridge-transfer-restriction-bypass.yaml"
    WIKI_TITLE = "OFT transfer restriction enforced only locally, not on bridge-credit"
    WIKI_DESCRIPTION = "Bridged tokens using OFT-style architecture expose two transfer surfaces: local `_transfer` and cross-chain `_credit`. When restrictions (KYC whitelist, blacklist, team-unlock schedule) live only in `_transfer`, an attacker bridges the token to another chain (or to a sibling OFT on the same chain) and has it credited to a fresh address that was never restricted. The restriction is washed."
    WIKI_EXPLOIT_SCENARIO = "THORWallet: team unlocked tokens have `lockUntil[alice] = day30`, checked in `_transfer`. Alice calls `send(chainId, bobOnOtherChain, amount)` which calls `_debit(alice, amount)`. If `_debit` misses the lock check (common — most OFT templates only guard `_transfer`), the debit succeeds. On the destination, `_credit(bobOnOtherChain, amount)` mints tokens. Alice bridges back to Alice's own address o"
    WIKI_RECOMMENDATION = "Push every restriction check into `_update` / base-class `_beforeTokenTransfer`, which both the local and cross-chain credit paths reach. Alternatively, attach cross-chain origin (srcAddress) metadata to the credit and enforce restrictions against that on local re-transfer."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(OFT|oft|_debit|_credit|send\\(|receive\\(|lzReceive)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '(_debit|_credit|_transfer|transfer|send)'}, {'function.body_contains_regex': '(whitelist|blacklist|isRestricted|transferDisabled|lockUntil)'}, {'contract.has_no_function_body_matching': 'function\\s+(_credit|lzReceive)[^{]*\\{[^}]*(whitelist|blacklist|isRestricted|transferDisabled|lockUntil)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — two-hop-bridge-transfer-restriction-bypass: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
