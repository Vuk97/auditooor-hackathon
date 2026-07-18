"""
arbitrum-l1-to-l2-sender-alias-not-handled — generated from reference/patterns.dsl/arbitrum-l1-to-l2-sender-alias-not-handled.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py arbitrum-l1-to-l2-sender-alias-not-handled.yaml
Source: auditooor-R73-chain-specific-arbitrum
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ArbitrumL1ToL2SenderAliasNotHandled(AbstractDetector):
    ARGUMENT = "arbitrum-l1-to-l2-sender-alias-not-handled"
    HELP = "Arbitrum applies a 0x1111…1111 alias offset to L1-originated msg.sender on L2. Contracts checking `msg.sender == knownL1Address` without un-aliasing reject legit messages or accept spoofed ones."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/arbitrum-l1-to-l2-sender-alias-not-handled.yaml"
    WIKI_TITLE = "Arbitrum L1→L2 msg.sender alias not un-aliased in cross-chain guard"
    WIKI_DESCRIPTION = "When an L1 contract sends a message to L2 via the Inbox, the L2-side message's msg.sender is the L1 contract address + `0x1111000000000000000000000000000000001111`. An L2 receiver that gates on `require(msg.sender == L1_GOVERNANCE)` will reject every real governance message. Worse: if the receiver forgets to gate at all and trusts any msg.sender >= some threshold, an attacker who deploys on L1 at "
    WIKI_EXPLOIT_SCENARIO = "A cross-chain governance bridge on Arbitrum has `onlyL1Governance` modifier: `require(msg.sender == L1_GOV_ADDRESS)`. Every legit L1 governance message arrives with msg.sender == L1_GOV_ADDRESS + 0x1111…1111, fails the check, reverts. Governance is frozen until operators realize and fix the alias handling. Alternatively, if a contract checks `msg.sender == L1_GOV + ALIAS` without proper masking (e"
    WIKI_RECOMMENDATION = "Import Arbitrum's `AddressAliasHelper.sol` and use `AddressAliasHelper.undoL1ToL2Alias(msg.sender) == EXPECTED_L1_ADDRESS`. Document which functions expect L1-aliased senders vs direct L2 callers. Add a fork-test on Arbitrum Sepolia asserting an L1-originated call passes the guard."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)onlyL1Sender|L1ToL2|crossChain|bridgeInbox'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.body_contains_regex': '(?i)(onlyL1Sender|expectedL1Sender|require\\s*\\(\\s*msg\\.sender\\s*==\\s*\\w*L1\\w*)'}, {'function.body_not_contains_regex': '(?i)(AddressAliasHelper|applyL1ToL2Alias|\\.\\s*sub\\s*\\(\\s*offset|0x1111000000000000000000000000000000001111|L1_TO_L2_ALIAS_OFFSET)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — arbitrum-l1-to-l2-sender-alias-not-handled: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
