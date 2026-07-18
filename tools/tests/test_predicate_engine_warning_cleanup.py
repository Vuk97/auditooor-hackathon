from __future__ import annotations

import importlib.util
import io
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace


REPO = Path(__file__).resolve().parents[2]
ENGINE = REPO / "detectors" / "_predicate_engine.py"


def _load_engine():
    spec = importlib.util.spec_from_file_location("_predicate_engine_warning_cleanup", ENGINE)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _source(text: str):
    return SimpleNamespace(content=text)


def _contract(name: str = "StrategyWrapper", source: str = "", parents=()):
    return SimpleNamespace(
        name=name,
        inheritance=[SimpleNamespace(name=p) for p in parents],
        source_mapping=_source(source),
        state_variables=[],
        variables=[],
        functions=[],
    )


def _function(contract, name: str = "withdraw"):
    return SimpleNamespace(
        name=name,
        contract=contract,
        contract_declarer=contract,
        source_mapping=_source("function withdraw() external {}"),
        nodes=[],
        modifiers=[],
        parameters=[],
    )


class PredicateEngineWarningCleanupTest(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = _load_engine()
        self.engine._UNKNOWN_PREDICATE_WARNED.clear()

    def test_contract_aliases_match_without_unknown_warnings(self) -> None:
        contract = _contract(
            source="contract StrategyWrapper is ERC20Upgradeable { UserCheckpoint storage checkpoint; }",
            parents=("ERC20Upgradeable",),
        )
        err = io.StringIO()
        with redirect_stderr(err):
            matched = self.engine.eval_preconditions(
                contract,
                [
                    {"contract.name_matches": "strategy"},
                    {"contract.inherits_regex": "ERC20"},
                    {"contract.body_contains_regex": "UserCheckpoint"},
                    {"contract.body_not_contains_regex": "function\\s+_update\\s*\\("},
                ],
            )

        self.assertTrue(matched)
        self.assertEqual(err.getvalue(), "")

    def test_function_match_can_apply_contract_scoped_predicates(self) -> None:
        contract = _contract(
            source="contract StrategyWrapper is ERC20 { mapping(address => UserCheckpoint) userCheckpoints; }",
            parents=("ERC20",),
        )
        function = _function(contract)
        err = io.StringIO()
        with redirect_stderr(err):
            matched = self.engine.eval_function_match(
                function,
                [
                    {"contract.inherits_regex": "ERC20"},
                    {"contract.body_contains_regex": "userCheckpoints"},
                    {"contract.not_in_skip_list": True},
                ],
            )

        self.assertTrue(matched)
        self.assertEqual(err.getvalue(), "")

    def test_zk_circuit_domain_gate_fails_closed_without_warning_spam(self) -> None:
        contract = _contract(source="contract PlainSolidity {}")
        err = io.StringIO()
        with redirect_stderr(err):
            first = self.engine.eval_preconditions(contract, [{"chain.is_zk_circuit": True}])
            second = self.engine.eval_preconditions(contract, [{"chain.is_zk_circuit": True}])

        self.assertFalse(first)
        self.assertFalse(second)
        self.assertEqual(err.getvalue(), "")

    def test_unknown_predicate_still_fails_closed_but_warns_once_per_key(self) -> None:
        contract = _contract()
        err = io.StringIO()
        with redirect_stderr(err):
            first = self.engine.eval_preconditions(contract, [{"contract.typo_predicate": True}])
            second = self.engine.eval_preconditions(contract, [{"contract.typo_predicate": True}])

        self.assertFalse(first)
        self.assertFalse(second)
        lines = [line for line in err.getvalue().splitlines() if line]
        self.assertEqual(len(lines), 1)
        self.assertIn("UNKNOWN contract predicate key 'contract.typo_predicate'", lines[0])


if __name__ == "__main__":
    unittest.main()
