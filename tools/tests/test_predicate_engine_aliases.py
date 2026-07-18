#!/usr/bin/env python3
from __future__ import annotations

import sys
import unittest
import importlib.util
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from detectors._predicate_engine import (  # noqa: E402
    eval_function_match,
    _check_contract_pred,
    _check_function_pred,
    _modifier_names,
    _parse_bang_predicate_string,
)


def _load_packaged_engine():
    path = (
        ROOT
        / "packaging"
        / "auditooor_detectors"
        / "auditooor_detectors"
        / "detectors"
        / "_predicate_engine.py"
    )
    spec = importlib.util.spec_from_file_location("packaged_predicate_engine", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class PredicateEngineAliasTests(unittest.TestCase):
    def test_safe_contract_aliases_match_canonical_predicates(self) -> None:
        contract = SimpleNamespace(
            functions=[
                SimpleNamespace(
                    name="withdraw",
                    source_mapping=SimpleNamespace(
                        content="function withdraw() external { token.transfer(msg.sender, amount); }"
                    ),
                ),
                SimpleNamespace(
                    name="deposit",
                    source_mapping=SimpleNamespace(content="function deposit() external {}"),
                ),
            ],
            state_variables=[SimpleNamespace(name="owner")],
            source_mapping=SimpleNamespace(content="contract Vault { address owner; }"),
        )
        cases = [
            ("contract.has_func_matching", "contract.has_function_matching", "with"),
            (
                "contract.has_func_body_matching",
                "contract.has_function_body_matching",
                "token\\.transfer",
            ),
            (
                "contract.has_func_body_matching_invert",
                "contract.has_no_function_body_matching",
                "safeTransfer",
            ),
            ("contract.has_field_matching", "contract.has_state_var_matching", "owner"),
            ("contract.source_contains_regex", "contract.source_matches_regex", "owner"),
            ("repo.source_matches_regex", "contract.source_matches_regex", "owner"),
        ]

        for alias, canonical, value in cases:
            with self.subTest(alias=alias):
                self.assertEqual(
                    _check_contract_pred(contract, alias, value),
                    _check_contract_pred(contract, canonical, value),
                )

    def test_packaged_engine_alias_maps_stay_in_sync(self) -> None:
        packaged = _load_packaged_engine()
        from detectors import _predicate_engine as root_engine

        self.assertEqual(
            packaged._CONTRACT_PREDICATE_ALIASES,
            root_engine._CONTRACT_PREDICATE_ALIASES,
        )
        self.assertEqual(
            packaged._FUNCTION_PREDICATE_ALIASES,
            root_engine._FUNCTION_PREDICATE_ALIASES,
        )

    def test_safe_function_aliases_match_canonical_predicates(self) -> None:
        fn = SimpleNamespace(
            name="withdraw",
            internal_calls=[SimpleNamespace(name="refreshLimit")],
            high_level_calls=[],
            nodes=[],
            modifiers=[SimpleNamespace(name="onlyOwner")],
            parameters=[
                SimpleNamespace(type="address", name="recipient"),
                SimpleNamespace(type="uint256", name="amount"),
            ],
            state_variables_written=[SimpleNamespace(name="balance")],
            source_mapping=SimpleNamespace(
                content="function withdraw() external { refreshLimit(); return 1; }"
            ),
            contract=SimpleNamespace(
                source_mapping=SimpleNamespace(content="contract Vault { address owner; }")
            ),
        )
        cases = [
            ("function.body_matches_regex", "function.body_contains_regex", "return\\s+1"),
            ("function.not_body_matches_regex", "function.body_not_contains_regex", "transfer\\("),
            (
                "function.contract_has_source_matching",
                "function.contract.source_matches_regex",
                "owner",
            ),
            (
                "function.not_calls_function_matching",
                "function.does_not_call_matching",
                "updateDailyLimit",
            ),
            ("function.not_in_slither_synthetic", "function.not_slither_synthetic", True),
            ("function.body_not_matches_regex", "function.body_not_contains_regex", "transfer\\("),
            ("function.has_modifier_regex", "function.has_modifier_matching", "onlyOwner"),
            ("function.modifier_not_matches_regex", "function.not_modifiers_match", "onlyAdmin"),
            ("function.modifiers_not_matching", "function.not_modifiers_match", "onlyAdmin"),
            ("function.has_modifier_not", "function.not_modifiers_match", "onlyAdmin"),
            ("function.parameter_named", "function.has_param_name_matching", "recipient"),
            ("function.parameter_matches_regex", "function.parameters_include", "address\\s+recipient"),
            ("function.parameter_not_matches_regex", "function.parameters_not_include", "bytes\\s+data"),
            ("function.param_list_contains_regex", "function.parameters_include", "uint256\\s+amount"),
            ("function.signature_matches_regex", "function.signature_regex", "uint256\\s+amount"),
            (
                "function.writes_state_var_matches",
                "function.writes_state_var_matching_regex",
                "balance",
            ),
        ]

        for alias, canonical, value in cases:
            with self.subTest(alias=alias):
                self.assertEqual(
                    _check_function_pred(fn, alias, value),
                    _check_function_pred(fn, canonical, value),
                )

    def test_not_body_contains_alias_matches_existing_inverse(self) -> None:
        fn = SimpleNamespace(source_mapping=SimpleNamespace(content="function f() public { return 1; }"))
        self.assertTrue(_check_function_pred(fn, "function.not_body_contains_regex", "transfer\\("))
        self.assertFalse(_check_function_pred(fn, "function.not_body_contains_regex", "return\\s+1"))

    def test_contract_source_alias_works_from_function_prefixed_key(self) -> None:
        contract = SimpleNamespace(source_mapping=SimpleNamespace(content="contract Vault { address owner; }"))
        self.assertTrue(_check_contract_pred(contract, "function.contract.source_matches_regex", "owner"))
        self.assertFalse(_check_contract_pred(contract, "function.contract.source_matches_regex", "guardian"))

    def test_contract_not_source_alias_works_from_function_prefixed_key(self) -> None:
        contract = SimpleNamespace(source_mapping=SimpleNamespace(content="contract OwnableVault { address owner; }"))
        self.assertTrue(_check_contract_pred(contract, "function.contract.not_source_matches_regex", "Ownable2Step"))
        self.assertFalse(_check_contract_pred(contract, "function.contract.not_source_matches_regex", "Ownable"))

    def test_high_level_call_named_accepts_function_name_shape(self) -> None:
        call = SimpleNamespace(function_name="safeTransfer")
        fn = SimpleNamespace(nodes=[SimpleNamespace(high_level_calls=[call])])
        self.assertTrue(_check_function_pred(fn, "function.has_high_level_call_named", "safeTransfer"))

    def test_high_level_call_named_accepts_function_object_shape(self) -> None:
        call = SimpleNamespace(function=SimpleNamespace(name="sweep"))
        fn = SimpleNamespace(nodes=[SimpleNamespace(high_level_calls=[call])])
        self.assertTrue(_check_function_pred(fn, "function.has_high_level_call_named", "sweep"))

    def test_name_matches_regex_alias_matches_function_name(self) -> None:
        fn = SimpleNamespace(name="heal")
        self.assertTrue(_check_function_pred(fn, "function.name_matches_regex", "heal|move|flop"))
        self.assertFalse(_check_function_pred(fn, "function.name_matches_regex", "kick"))

    def test_writes_state_var_matching_regex_alias_matches_state_writes(self) -> None:
        fn = SimpleNamespace(state_variables_written=[SimpleNamespace(name="flop")])
        self.assertTrue(
            _check_function_pred(
                fn,
                "function.writes_state_var_matching_regex",
                "flop|heal|move",
            )
        )
        self.assertFalse(
            _check_function_pred(
                fn,
                "function.writes_state_var_matching_regex",
                "surplus",
            )
        )

    def test_parameters_include_matches_param_type_and_name(self) -> None:
        fn = SimpleNamespace(
            parameters=[
                SimpleNamespace(type="bytes", name="data"),
                SimpleNamespace(type="address", name="recipient"),
            ]
        )
        self.assertTrue(
            _check_function_pred(fn, "function.parameters_include", r"(bytes|calldata)\s+data")
        )
        self.assertFalse(
            _check_function_pred(fn, "function.parameters_include", r"uint256\s+amount")
        )

    def test_has_address_parameter_has_dedicated_boolean_semantics(self) -> None:
        with_address = SimpleNamespace(parameters=[SimpleNamespace(type="address payable", name="to")])
        without_address = SimpleNamespace(parameters=[SimpleNamespace(type="uint256", name="amount")])

        self.assertTrue(_check_function_pred(with_address, "function.has_address_parameter", True))
        self.assertFalse(_check_function_pred(with_address, "function.has_address_parameter", False))
        self.assertFalse(_check_function_pred(without_address, "function.has_address_parameter", True))
        self.assertTrue(_check_function_pred(without_address, "function.has_address_parameter", False))
        self.assertFalse(_check_function_pred(with_address, "function.has_param_of_type", True))

    def test_modifier_names_ignores_nameless_object_repr(self) -> None:
        nameless = SimpleNamespace()
        fn = SimpleNamespace(modifiers=[SimpleNamespace(name="onlyOwner"), "whenNotPaused", nameless])

        self.assertEqual(_modifier_names(fn), ["onlyOwner", "whenNotPaused"])
        self.assertTrue(_check_function_pred(fn, "function.has_modifier_matching", "onlyOwner"))
        self.assertTrue(_check_function_pred(fn, "function.has_modifier_matching", "whenNotPaused"))
        self.assertFalse(_check_function_pred(fn, "function.has_modifier_matching", "namespace"))

    def test_signature_regex_matches_synthetic_signature(self) -> None:
        fn = SimpleNamespace(
            name="mint",
            parameters=[
                SimpleNamespace(type="address", name="recipient"),
                SimpleNamespace(type="uint256", name="amount"),
            ],
        )

        self.assertTrue(_check_function_pred(fn, "function.signature_regex", r"uint256\s+amount"))
        self.assertTrue(_check_function_pred(fn, "function.signature_regex", r"mint\(address"))
        self.assertFalse(_check_function_pred(fn, "function.signature_regex", r"bytes\s+data"))

    def test_exact_function_name_predicate(self) -> None:
        fn = SimpleNamespace(name="rebalance")

        self.assertTrue(_check_function_pred(fn, "function.name", "rebalance"))
        self.assertFalse(_check_function_pred(fn, "function.name", "withdraw"))

    def test_parameter_name_predicates_cover_canonical_paths(self) -> None:
        fn = SimpleNamespace(
            parameters=[
                SimpleNamespace(type="address", name="recipient"),
                SimpleNamespace(type="uint256", name="amount"),
            ]
        )

        self.assertTrue(_check_function_pred(fn, "function.has_param_name_matching", "recipient"))
        self.assertTrue(_check_function_pred(fn, "function.parameter_names_match", r"^recipient,amount$"))
        self.assertFalse(_check_function_pred(fn, "function.parameter_names_match", r"^amount,recipient$"))
        self.assertTrue(_check_function_pred(fn, "function.parameters_not_include", r"bytes\s+data"))
        self.assertFalse(_check_function_pred(fn, "function.parameters_not_include", r"uint256\s+amount"))

    def test_contract_inherits_accepts_scalar_and_list(self) -> None:
        contract = SimpleNamespace(
            name="Vault",
            inheritance=[SimpleNamespace(name="Ownable"), SimpleNamespace(name="Pausable")],
        )

        self.assertTrue(_check_contract_pred(contract, "contract.inherits", "Ownable"))
        self.assertTrue(_check_contract_pred(contract, "contract.inherits", ["ERC20", "Pausable"]))
        self.assertFalse(_check_contract_pred(contract, "contract.inherits", "ERC20"))
        self.assertFalse(_check_contract_pred(contract, "contract.inherits", ["ERC20", "ERC4626"]))

    def test_contract_precondition_function_predicates_use_any_declared_function(self) -> None:
        contract = SimpleNamespace(
            functions=[
                SimpleNamespace(name="deposit", parameters=[]),
                SimpleNamespace(name="withdraw", parameters=[SimpleNamespace(type="address", name="to")]),
            ]
        )

        self.assertTrue(_check_contract_pred(contract, "function.name", "withdraw"))
        self.assertTrue(_check_contract_pred(contract, "function.has_address_parameter", True))
        self.assertFalse(_check_contract_pred(contract, "function.name", "harvest"))

    def test_domain_gates_fail_closed_without_unknown_warning(self) -> None:
        contract = SimpleNamespace(name="Vault")
        for key in (
            "chain.is_cosmos_sdk",
            "chain.is_btc_spv_verifier",
            "chain.is_l2_with_shadow_eth_erc20",
            "crate.source_matches_regex",
        ):
            with self.subTest(key=key):
                self.assertFalse(_check_contract_pred(contract, key, True))
                self.assertTrue(_check_contract_pred(contract, key, False))

    def test_literal_source_contains_predicates(self) -> None:
        contract = SimpleNamespace(source_mapping=SimpleNamespace(content="contract Vault { address owner; }"))
        fn = SimpleNamespace(
            source_mapping=SimpleNamespace(
                content="function addBackingToken(address token) external { backingTokens.push(token); }"
            )
        )

        self.assertTrue(_check_contract_pred(contract, "contract.source_contains", "address owner"))
        self.assertTrue(_check_contract_pred(contract, "contract.not_source_contains", "function removeOwner"))
        self.assertTrue(
            _check_contract_pred(
                contract,
                "contract.source_contains_any",
                ["missing", "address owner"],
            )
        )
        self.assertTrue(
            _check_contract_pred(
                contract,
                "contract.source_contains_all",
                ["contract Vault", "address owner"],
            )
        )
        self.assertTrue(_check_function_pred(fn, "function.source_contains", "backingTokens.push"))
        self.assertTrue(_check_function_pred(fn, "function.source_not_contains", "backingTokens.pop"))
        self.assertTrue(
            _check_function_pred(
                fn,
                "function.source_contains_all",
                ["addBackingToken", "backingTokens.push"],
            )
        )

    def test_parse_bang_predicate_string_edge_cases(self) -> None:
        self.assertEqual(
            _parse_bang_predicate_string("!function.body_contains_regex: 'foo:bar'"),
            ("function.body_contains_regex", "foo:bar"),
        )
        self.assertEqual(
            _parse_bang_predicate_string('!function.name: "transfer"'),
            ("function.name", "transfer"),
        )
        self.assertEqual(
            _parse_bang_predicate_string("!function.source_contains: http://example.invalid/path"),
            ("function.source_contains", "http://example.invalid/path"),
        )
        self.assertEqual(
            _parse_bang_predicate_string("!function.is_constructor: true"),
            ("function.is_constructor", True),
        )
        self.assertEqual(
            _parse_bang_predicate_string("!function.is_constructor: false"),
            ("function.is_constructor", False),
        )
        self.assertIsNone(_parse_bang_predicate_string("function.name: transfer"))
        self.assertIsNone(_parse_bang_predicate_string("!function.name"))

    def test_bang_predicate_string_negates_embedded_predicate(self) -> None:
        clean = SimpleNamespace(
            source_mapping=SimpleNamespace(content="function reallocate() external { pool.slot0(); }")
        )
        guarded = SimpleNamespace(
            source_mapping=SimpleNamespace(
                content="function reallocate() external { pool.slot0(); pool.observe(secondsAgo); }"
            )
        )

        predicate = "!function.body_contains_regex: '(?i)(observe\\s*\\()'"
        self.assertTrue(eval_function_match(clean, [predicate]))
        self.assertFalse(eval_function_match(guarded, [predicate]))

    def test_body_ordered_regex_matches_later_source_region(self) -> None:
        fn = SimpleNamespace(
            source_mapping=SimpleNamespace(
                content="""
                function withdraw(address user, address token) external {
                    userRewardDebts[user][token] = 0;
                    cachedUserRewards[user][token] += rewardDebtDiff - userRewardDebts[user][token];
                }
                """
            )
        )

        self.assertTrue(
            eval_function_match(
                fn,
                [
                    {
                        "function.body_ordered_regex": {
                            "first": r"userRewardDebts\s*\[[^\]]+\]\s*\[[^\]]+\]\s*=\s*0",
                            "second": r"cachedUserRewards\s*\[[^\]]+\]\s*\[[^\]]+\]\s*\+=",
                        }
                    }
                ],
            )
        )

    def test_body_contains_regex_ordered_legacy_list_alias(self) -> None:
        fn = SimpleNamespace(
            source_mapping=SimpleNamespace(
                content="""
                function buy() external {
                    msg.sender.call{value: refund}("");
                    lastTradeTimestamp[msg.sender] = block.timestamp;
                }
                """
            )
        )

        self.assertTrue(
            eval_function_match(
                fn,
                [
                    {
                        "function.body_contains_regex_ordered": [
                            r"call\{value:",
                            r"lastTradeTimestamp\s*\[[^\]]+\]\s*=\s*block\.timestamp",
                        ]
                    }
                ],
            )
        )

    def test_body_ordered_regex_rejects_reversed_order(self) -> None:
        fn = SimpleNamespace(
            source_mapping=SimpleNamespace(
                content="""
                function withdraw(address user, address token) external {
                    cachedUserRewards[user][token] += rewardDebtDiff - userRewardDebts[user][token];
                    userRewardDebts[user][token] = 0;
                }
                """
            )
        )

        self.assertFalse(
            eval_function_match(
                fn,
                [
                    {
                        "function.body_ordered_regex": {
                            "first": r"userRewardDebts\s*\[[^\]]+\]\s*\[[^\]]+\]\s*=\s*0",
                            "second": r"cachedUserRewards\s*\[[^\]]+\]\s*\[[^\]]+\]\s*\+=",
                        }
                    }
                ],
            )
        )

    def test_body_ordered_regex_can_ignore_comment_and_string_bait(self) -> None:
        fn = SimpleNamespace(
            source_mapping=SimpleNamespace(
                content='''
                function withdraw(address user, address token) external {
                    cachedUserRewards[user][token] += rewardDebtDiff - userRewardDebts[user][token];
                    userRewardDebts[user][token] = 0;
                    // userRewardDebts[user][token] = 0;
                    string memory bait = "cachedUserRewards[user][token] += rewardDebtDiff - userRewardDebts[user][token];";
                }
                '''
            )
        )

        self.assertFalse(
            eval_function_match(
                fn,
                [
                    {
                        "function.body_ordered_regex": {
                            "first": r"userRewardDebts\s*\[[^\]]+\]\s*\[[^\]]+\]\s*=\s*0",
                            "second": r"cachedUserRewards\s*\[[^\]]+\]\s*\[[^\]]+\]\s*\+=",
                            "ignore_comments_and_strings": True,
                        }
                    }
                ],
            )
        )

    def test_body_ordered_regex_keeps_code_after_slashes_inside_string(self) -> None:
        fn = SimpleNamespace(
            source_mapping=SimpleNamespace(
                content='''
                function withdraw(address user, address token) external {
                    string memory url = "https://example.invalid/path";
                    userRewardDebts[user][token] = 0;
                    cachedUserRewards[user][token] += rewardDebtDiff - userRewardDebts[user][token];
                }
                '''
            )
        )

        self.assertTrue(
            eval_function_match(
                fn,
                [
                    {
                        "function.body_ordered_regex": {
                            "first": r"userRewardDebts\s*\[[^\]]+\]\s*\[[^\]]+\]\s*=\s*0",
                            "second": r"cachedUserRewards\s*\[[^\]]+\]\s*\[[^\]]+\]\s*\+=",
                            "ignore_comments_and_strings": True,
                        }
                    }
                ],
            )
        )


if __name__ == "__main__":
    unittest.main()
