"""
gas-refund-miscomputed-block-vs-tx — generated from reference/patterns.dsl/gas-refund-miscomputed-block-vs-tx.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py gas-refund-miscomputed-block-vs-tx.yaml
Source: solodit-cluster-C0153
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GasRefundMiscomputedBlockVsTx(AbstractDetector):
    ARGUMENT = "gas-refund-miscomputed-block-vs-tx"
    HELP = "Refund amount is computed from block.gaslimit or gasleft() sampled at the wrong CFG position, causing over- or under-refund of the caller."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/gas-refund-miscomputed-block-vs-tx.yaml"
    WIKI_TITLE = "Gas refund miscomputed: block.gaslimit used instead of transaction gas"
    WIKI_DESCRIPTION = "Relayer and meta-tx payout routines must reimburse the submitter based on gas actually spent in this transaction. Computing the refund against `block.gaslimit` (a block-wide header value that any single transaction rarely hits) or sampling `gasleft()` at the wrong CFG position (before vs after the heavy work) inflates or deflates the reimbursement, draining the relayer float or under-paying keeper"
    WIKI_EXPLOIT_SCENARIO = "A meta-tx relayer computes refund as `refund = block.gaslimit * tx.gasprice`. Because `block.gaslimit` is far larger than the gas any one transaction actually burns, every relayed call drains the relayer's deposit for the full block budget rather than the real spend. Conversely, a keeper contract that samples `gasleft()` before doing the work under-reports spend and consistently under-pays keepers"
    WIKI_RECOMMENDATION = "Refund based on a pre/post-execution gasleft() delta: `uint256 startGas = gasleft();` at the top, `uint256 used = startGas - gasleft() + FIXED_OVERHEAD;` after the work, then `refund = used * tx.gasprice`. Never use `block.gaslimit` for per-transaction refund math. Cap refunds at `msg.gas` or a conf"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': 'block\\.gaslimit|gasleft\\s*\\(\\s*\\)|_refundGas|gas_refund|gasRefund'}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.body_contains_regex': '_refund|\\.transfer\\s*\\(\\s*msg\\.sender|\\.call\\s*\\{\\s*value'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — gas-refund-miscomputed-block-vs-tx: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
