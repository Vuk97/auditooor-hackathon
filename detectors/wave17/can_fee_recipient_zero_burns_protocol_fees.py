"""
can-fee-recipient-zero-burns-protocol-fees — generated from reference/patterns.dsl/can-fee-recipient-zero-burns-protocol-fees.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py can-fee-recipient-zero-burns-protocol-fees.yaml
Source: cantina/2024-2025-fee-recipient-zero-burn-class
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CanFeeRecipientZeroBurnsProtocolFees(AbstractDetector):
    ARGUMENT = "can-fee-recipient-zero-burns-protocol-fees"
    HELP = "feeRecipient setter allows `address(0)` — fees either burn on legacy ERC20s or revert every user tx on OZ-compliant tokens, depending on the token implementation."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/can-fee-recipient-zero-burns-protocol-fees.yaml"
    WIKI_TITLE = "Fee recipient setter lacks zero-address guard"
    WIKI_DESCRIPTION = "Every setter that writes to a storage slot used as the destination of an unconditional `token.transfer(feeRecipient, fee)` must reject `address(0)`. OpenZeppelin ERC20 reverts on transfers to zero, so the user-facing tx that charges the fee will revert — a full-path DoS on the protocol's hot surface. Legacy ERC20s (no zero check) will instead silently burn the fee, permanently reducing protocol re"
    WIKI_EXPLOIT_SCENARIO = "Cantina competition class: admin (or an uncapped constructor) sets `feeRecipient = address(0)` by mistake, or a multisig rotation accidentally passes zero, or a chain deployment omits the initialization tx. Every swap / redeem / deposit that charges a fee now reverts on the OZ SafeERC20 path (or mints dust into 0x0 on legacy tokens). Users cannot interact with the protocol until the recipient is r"
    WIKI_RECOMMENDATION = "Guard every recipient setter: `require(newRecipient != address(0), \"zero recipient\");`. Apply the same check inside constructors, initializers, and multi-sig rotation functions. Optional defense-in-depth: skip the fee leg when `feeRecipient == address(0)` instead of reverting, so admin mistakes do"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_declaration_matching': '(feeRecipient|feeReceiver|treasury|protocolFeeRecipient)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(setFeeRecipient|setFeeReceiver|setTreasury|setProtocolFeeRecipient|initialize)'}, {'function.body_contains_regex': '(feeRecipient|feeReceiver|treasury|protocolFeeRecipient)\\s*=\\s*\\w+'}, {'function.body_not_contains_regex': 'require\\s*\\([^)]*!=\\s*address\\s*\\(\\s*0\\s*\\)|!=\\s*address\\s*\\(\\s*0\\s*\\)\\s*,|revert\\s+\\w*Zero\\w*|ZeroAddress'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — can-fee-recipient-zero-burns-protocol-fees: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
