"""
evmos-bank-send-to-blocklisted-module-account — generated from reference/patterns.dsl/evmos-bank-send-to-blocklisted-module-account.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py evmos-bank-send-to-blocklisted-module-account.yaml
Source: auditooor-R76-immunefi-evmos-$150k
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EvmosBankSendToBlocklistedModuleAccount(AbstractDetector):
    ARGUMENT = "evmos-bank-send-to-blocklisted-module-account"
    HELP = "Cosmos-SDK bank SendCoins doesn't check the destination against the blocked-module-accounts map. Sending to distribution/mint/fee_collector breaks invariants and halts the chain."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/evmos-bank-send-to-blocklisted-module-account.yaml"
    WIKI_TITLE = "Cosmos bank MsgSend allows transfers to blocklisted module accounts"
    WIKI_DESCRIPTION = "The Cosmos-SDK `x/bank` module ships with a configurable blocked-addresses map intended to prevent direct Send to module accounts (distribution rewards pool, mint pool, fee collector). If the chain's handler does not enforce `BlockedAddr(toAddr)` before calling SendCoins, any user can transfer coins directly into these accounts. Because the accounting invariants assume module-account balances are "
    WIKI_EXPLOIT_SCENARIO = "On Evmos, any user could execute `evmosd tx bank send <user> <distribution_module_addr> 1aevmos`. The distribution module's balance now exceeded its tracked total → next block BeginBlocker panicked with `invariant broken: distribution` → chain halts. $150k bounty."
    WIKI_RECOMMENDATION = "Every chain inheriting the Cosmos-SDK MUST populate the bank keeper's blocked-addresses list with ALL module accounts except those explicitly designed to receive user deposits (e.g. gov deposits). Add an automated config test that asserts `for acct in moduleAccounts: blockedAddrs[acct] || expectedRe"

    _PRECONDITIONS = [{'chain.is_cosmos_sdk': True}, {'contract.source_matches_regex': '(BankKeeper|x/bank|MsgServer|MsgSend|SendCoins|moduleAccount|ModuleAccount|cosmos-sdk|baseKeeper|BankSend)'}]
    _MATCH = [{'function.kind': 'cosmos_msg_handler'}, {'function.name_matches': '^(SendCoins|MsgSend|handleMsgSend|SendCoinsFromAccountToAccount|InputOutputCoins|sendCoinsToModule|transferCoin|transferCoins)\\w*$'}, {'function.body_not_contains_regex': '(?i)BlockedAddr\\s*\\(|IsBlockedAddr\\s*\\(|blocked_addresses\\.contains|blockedAddrs\\[\\s*to\\s*\\]'}, {'function.body_contains_regex': '(?i)SendCoins\\s*\\(\\s*\\w+,\\s*\\w+,\\s*toAddr|subUnlockedCoins|addCoins'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)(super\\.SendCoins|baseKeeper\\.SendCoins|view\\s+func|SendCoinsFromModuleToModule|SendCoinsFromModuleToAccount\\s*\\(|MintCoins|BurnCoins|requireModulePerm|moduleAddr\\s*==\\s*sender)'}]

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
                info = [f, f" — evmos-bank-send-to-blocklisted-module-account: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
