"""Row-level predicate aliases used by generated scanner wiring."""

from __future__ import annotations

import unittest
from types import SimpleNamespace

from detectors._predicate_engine import eval_function_match


def _function(*, name: str = "teleportBOBA", reads=(), internal_calls=(), source: str = ""):
    return SimpleNamespace(
        name=name,
        state_variables_read=[SimpleNamespace(name=item) for item in reads],
        internal_calls=[SimpleNamespace(name=item) for item in internal_calls],
        high_level_calls=[],
        nodes=[],
        source_mapping=SimpleNamespace(content=source),
    )


class PredicateEngineRowWiringTests(unittest.TestCase):
    def test_reads_state_var_matching_alias_matches_storage_reads(self) -> None:
        fn = _function(reads=["maxTransferAmountPerDay"])

        self.assertTrue(
            eval_function_match(
                fn,
                [{"function.reads_state_var_matching": "maxTransferAmountPerDay"}],
            )
        )
        self.assertTrue(
            eval_function_match(
                fn,
                [{"function.reads_state_var_matching_regex": "maxTransfer.*Day"}],
            )
        )

    def test_does_not_call_matching_alias_checks_calls_and_source_fallback(self) -> None:
        unsafe = _function(reads=["maxTransferAmountPerDay"])
        safe_by_call_graph = _function(reads=["maxTransferAmountPerDay"], internal_calls=["updateDailyLimit"])
        safe_by_source = _function(
            reads=["maxTransferAmountPerDay"],
            source="function teleportBOBA() external { updateDailyLimit(); }",
        )

        predicate = {"function.does_not_call_matching": ".*(accrue|update|sync|validate|check|refresh).*"}
        self.assertTrue(eval_function_match(unsafe, [predicate]))
        self.assertFalse(eval_function_match(safe_by_call_graph, [predicate]))
        self.assertFalse(eval_function_match(safe_by_source, [predicate]))

    def test_does_not_call_matching_regex_alias_is_supported(self) -> None:
        fn = _function(internal_calls=["refreshLimit"])

        self.assertFalse(
            eval_function_match(
                fn,
                [{"function.does_not_call_matching_regex": "refresh"}],
            )
        )


if __name__ == "__main__":
    unittest.main()
