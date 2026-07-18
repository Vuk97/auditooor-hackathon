"""
dh-odos-exchange-unset-to-receiver — generated from reference/patterns.dsl/dh-odos-exchange-unset-toReceiver.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py dh-odos-exchange-unset-toReceiver.yaml
Source: defihacklabs/ODOS-2025-01
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DhOdosExchangeUnsetToReceiver(AbstractDetector):
    ARGUMENT = "dh-odos-exchange-unset-to-receiver"
    HELP = "Aggregator swap transfers output to a `receiver` that may be address(0) — tokens stranded and recoverable by anyone."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/dh-odos-exchange-unset-toReceiver.yaml"
    WIKI_TITLE = "Aggregator swap missing zero-address guard on receiver"
    WIKI_DESCRIPTION = "Routers that accept a user-specified `receiver` and transfer output tokens to it must reject `address(0)` or default to `msg.sender`. Otherwise tokens going to the zero address are effectively burned (or, with a non-burn semantics token like USDT, stuck in the router, pullable by any sweep function)."
    WIKI_EXPLOIT_SCENARIO = "ODOS 2025-01: exchange function swap output was sent to `receiver` without zero-address check. A partially-crafted calldata with zeroed receiver field left USDT in the router; ODOS exposed a `rescueTokens(address)` intended for owner but callable by anyone, draining."
    WIKI_RECOMMENDATION = "`require(receiver != address(0), \"zero receiver\")` or fall back to `msg.sender`. Audit any `rescueTokens`/`sweep` function for access control."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'swap|IAggregationRouter|SwapCompact'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': 'receiver|recipient|to\\s*='}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.body_contains_regex': '\\.transfer\\s*\\(\\s*(receiver|recipient|to)\\s*,|\\.safeTransfer\\s*\\(\\s*(receiver|recipient|to)\\s*,'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*(receiver|recipient|to)\\s*!=\\s*address\\s*\\(\\s*0\\s*\\)|if\\s*\\(\\s*(receiver|recipient|to)\\s*==\\s*address\\s*\\(\\s*0\\s*\\)\\s*\\)\\s*\\{?\\s*(receiver|recipient|to)\\s*=\\s*msg\\.sender'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — dh-odos-exchange-unset-to-receiver: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
