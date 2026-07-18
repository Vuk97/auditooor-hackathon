"""
missing-recipient-validation-transfer-or-credit - generated from reference/patterns.dsl/missing-recipient-validation-transfer-or-credit.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py missing-recipient-validation-transfer-or-credit.yaml
Source: capability-lift/P1-03-missing-recipient-validation
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MissingRecipientValidationTransferOrCredit(AbstractDetector):
    ARGUMENT = "missing-recipient-validation-transfer-or-credit"
    HELP = "Transfer, payout, mint, bridge, or order path accepts a recipient-like address parameter and later transfers, credits, or binds ownership to it without validating the receiver property required by the protocol."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/missing-recipient-validation-transfer-or-credit.yaml"
    WIKI_TITLE = "Missing recipient validation before transfer, credit, or ownership binding"
    WIKI_DESCRIPTION = "This pattern generalizes missing-recipient-validation findings where a token, asset, share, order, or bridge path accepts `recipient`, `receiver`, `beneficiary`, `account`, or `to` and later sends funds, mints shares, credits balances, or binds order ownership to that address. The vulnerable shape is not the mere presence of a receiver parameter; it is using that receiver as the value-bearing endp"
    WIKI_EXPLOIT_SCENARIO = "A caller supplies an arbitrary receiver-like address to a value-bearing entrypoint. The function later transfers tokens, mints shares, records credit, creates an order owner, or routes bridge proceeds to that address without checking the expected recipient domain. Depending on the protocol, this can create phantom deposits, strand funds at an invalid receiver, route value to the wrong account, or "
    WIKI_RECOMMENDATION = "Validate the receiver before value movement or ownership binding. Common fixes are `recipient != address(0)`, `recipient != address(this)`, `recipient == msg.sender` where third-party recipients are unsupported, comparison with the expected escrow or order owner, allowlist membership, or ERC721/ERC1"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)\\b(recipient|receiver|beneficiary|account|to)\\b'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(?i)(deposit|withdraw|claim|payout|pay|transfer|send|mint|redeem|fill|settle|bridge|process|execute|create)'}, {'function.parameters_include': '(?i)\\baddress\\s+(recipient|receiver|beneficiary|account|to)\\b'}, {'function.body_contains_regex': '(?i)\\b(recipient|receiver|beneficiary|account|to)\\b'}, {'function.body_contains_regex': '(?i)(safeTransfer|transfer\\s*\\(|transferFrom|_safeMint|_mint\\s*\\(|mintBehalf|mint\\s*\\(|sendValue|call\\s*\\{value:|balances?\\s*\\[|credits?\\s*\\[|orders?\\s*\\[|orderOwner\\s*\\[|ownerOf|recipientOf|receiverOf|beneficiaryOf)'}, {'function.body_not_contains_regex': '(?i)((recipient|receiver|beneficiary|account|to)\\s*(?:!=|==)\\s*address\\s*\\(\\s*0\\s*\\)|address\\s*\\(\\s*0\\s*\\)\\s*(?:!=|==)\\s*(recipient|receiver|beneficiary|account|to)|(recipient|receiver|beneficiary|account|to)\\s*(?:!=|==)\\s*address\\s*\\(\\s*this\\s*\\)|address\\s*\\(\\s*this\\s*\\)\\s*(?:!=|==)\\s*(recipient|receiver|beneficiary|account|to)|ZeroRecipient|InvalidRecipient|ZeroAddress|InvalidReceiver|expectedRecipient|trustedRecipient|recipientAllowlist|allowedRecipients|whitelistedRecipient|recipient\\s*(?:==|!=)\\s*msg\\.sender|receiver\\s*(?:==|!=)\\s*msg\\.sender|beneficiary\\s*(?:==|!=)\\s*msg\\.sender|account\\s*(?:==|!=)\\s*msg\\.sender|to\\s*(?:==|!=)\\s*msg\\.sender|code\\.length|onERC721Received|onERC1155Received)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}]

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
                info = [f, f" - missing-recipient-validation-transfer-or-credit: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
