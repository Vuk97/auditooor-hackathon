"""
r94-reverse-fee-charged-to-wrong-party — generated from reference/patterns.dsl/r94-reverse-fee-charged-to-wrong-party.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-reverse-fee-charged-to-wrong-party.yaml
Source: reverse-port-from-rust_wave1
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94ReverseFeeChargedToWrongParty(AbstractDetector):
    ARGUMENT = "r94-reverse-fee-charged-to-wrong-party"
    HELP = "Protocol fee is taken from the `recipient` / `to` side of a transfer rather than the `msg.sender` / payer — wrong party pays the protocol fee."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-reverse-fee-charged-to-wrong-party.yaml"
    WIKI_TITLE = "Protocol fee deducted from recipient instead of sender"
    WIKI_DESCRIPTION = "Protocols that charge a percentage fee on swaps, deposits, or transfers MUST deduct the fee from the caller (msg.sender / payer / from) and deliver the net amount to the recipient, OR they must deliver gross to the recipient and also pull the fee separately from the caller. A common implementation bug is to subtract the fee from the recipient's incoming leg while the caller pays the gross amount —"
    WIKI_EXPLOIT_SCENARIO = "DEX aggregator's `executeSwap(from, to, amount)` computes `uint fee = amount * 30 / 10000;` and then calls `token.safeTransferFrom(to, treasury, fee);` — pulling the fee OUT of the RECIPIENT's balance. A relayer calls the aggregator on behalf of a user; the user signs an approval to the aggregator for `amount` but ALSO has a lingering approval covering `fee`. The aggregator silently drains `fee` f"
    WIKI_RECOMMENDATION = "Adopt the Uniswap V3 / Curve convention: the payer (`from` / `msg.sender`) always pays the fee, and the recipient receives the net. Explicitly: `token.safeTransferFrom(from, feeRecipient, fee); token.safeTransferFrom(from, to, amount - fee);` — NEVER `token.safeTransferFrom(to, feeRecipient, fee)`. "

    _PRECONDITIONS = [{'contract.source_matches_regex': '(protocolFee|platformFee|treasuryFee|serviceFee|performanceFee)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '(uint\\d*|UFixed|uint)\\s+(fee|protocolFee|platformFee|treasuryFee|serviceFee)\\s*=\\s*[^;]*\\*\\s*[^;]*\\s*/\\s*(10000|1e4|BASIS_POINTS|BPS|PRECISION|WAD)'}, {'function.body_contains_regex': '(safeTransferFrom|transferFrom)\\s*\\(\\s*(recipient|to|receiver|beneficiary|out|dst|destination)\\b'}, {'function.body_not_contains_regex': '(transferFrom|safeTransferFrom)\\s*\\(\\s*(msg\\.sender|payer|_from|from|caller|sender)\\s*,\\s*\\w*(treasury|feeRecipient|protocolVault|feeCollector)\\w*\\s*,\\s*(fee|protocolFee|platformFee)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r94-reverse-fee-charged-to-wrong-party: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
