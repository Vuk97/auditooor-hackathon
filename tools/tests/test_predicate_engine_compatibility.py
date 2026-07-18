from __future__ import annotations

import contextlib
import io
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from detectors._predicate_engine import (  # noqa: E402
    _UNKNOWN_PREDICATE_WARNED,
    _check_contract_pred,
    _check_function_pred,
)


def _source(text: str) -> SimpleNamespace:
    return SimpleNamespace(content=text)


def _function(name: str, source: str, *, is_constructor: bool = False) -> SimpleNamespace:
    return SimpleNamespace(
        name=name,
        source_mapping=_source(source),
        is_constructor=is_constructor,
        nodes=[],
        modifiers=[],
        parameters=[],
    )


class PredicateEngineCompatibilityTests(unittest.TestCase):
    def test_contract_has_multiple_funcs_doing_requires_two_function_bodies(self) -> None:
        contract = SimpleNamespace(
            functions=[
                _function("prepare", "function prepare() { ecrecover(hash, v, r, s); }"),
                _function("addPeer", "function addPeer() { checkSignatures(hash, sigs); }"),
            ]
        )
        self.assertTrue(
            _check_contract_pred(
                contract,
                "contract.has_multiple_funcs_doing",
                "checkSignatures|ecrecover",
            )
        )

        one_match = SimpleNamespace(
            functions=[
                _function("prepare", "function prepare() { ecrecover(hash, v, r, s); }"),
                _function("plain", "function plain() { return; }"),
            ]
        )
        self.assertFalse(
            _check_contract_pred(
                one_match,
                "contract.has_multiple_funcs_doing",
                "checkSignatures|ecrecover",
            )
        )

    def test_contract_is_upgradeable_impl_detects_parent_or_upgrade_surface(self) -> None:
        inherited = SimpleNamespace(
            name="Impl",
            inheritance=[SimpleNamespace(name="UUPSUpgradeable")],
            source_mapping=_source("contract Impl is UUPSUpgradeable {}"),
        )
        self.assertTrue(_check_contract_pred(inherited, "contract.is_upgradeable_impl", True))

        source_only = SimpleNamespace(
            name="Impl",
            inheritance=[],
            source_mapping=_source("function _authorizeUpgrade(address next) internal {}"),
        )
        self.assertTrue(_check_contract_pred(source_only, "contract.is_upgradeable_impl", True))

        ordinary = SimpleNamespace(
            name="Plain",
            inheritance=[],
            source_mapping=_source("contract Plain { function set(uint256 x) external {} }"),
        )
        self.assertFalse(_check_contract_pred(ordinary, "contract.is_upgradeable_impl", True))
        self.assertTrue(_check_contract_pred(ordinary, "contract.is_upgradeable_impl", False))

    def test_contract_constructor_not_calls_regex_checks_constructor_body(self) -> None:
        disabled = SimpleNamespace(
            functions=[
                _function("constructor", "constructor() { _disableInitializers(); }", is_constructor=True),
                _function("initialize", "function initialize() external {}"),
            ]
        )
        self.assertFalse(
            _check_contract_pred(disabled, "contract.constructor_not_calls_regex", "_disableInitializers")
        )

        missing = SimpleNamespace(
            functions=[
                _function("constructor", "constructor() { owner = msg.sender; }", is_constructor=True),
                _function("initialize", "function initialize() external {}"),
            ]
        )
        self.assertTrue(
            _check_contract_pred(missing, "contract.constructor_not_calls_regex", "_disableInitializers")
        )

    def test_recipient_code_guard_or_tier_update_predicate_is_negative(self) -> None:
        vulnerable = _function(
            "transferCode",
            """
            function transferCode(address to) external {
                codeOwners[_code] = to;
                delete codes[msg.sender];
                codes[to] = _code;
            }
            """,
        )
        self.assertTrue(
            _check_function_pred(
                vulnerable,
                "function.body_lacks_recipient_code_guard_or_tier_update",
                True,
            )
        )

        guarded = _function(
            "transferCode",
            """
            function transferCode(address to) external {
                require(codes[to] == bytes32(0), "code exists");
                codeOwners[_code] = to;
                delete codes[msg.sender];
                codes[to] = _code;
            }
            """,
        )
        self.assertFalse(
            _check_function_pred(
                guarded,
                "function.body_lacks_recipient_code_guard_or_tier_update",
                True,
            )
        )

        tier_sync = _function(
            "transferCode",
            """
            function transferCode(address newOwner) external {
                codeOwners[_code] = newOwner;
                delete codes[msg.sender];
                codes[newOwner] = _code;
                referrerTiers[newOwner] = referrerTiers[msg.sender];
            }
            """,
        )
        self.assertFalse(
            _check_function_pred(
                tier_sync,
                "function.body_lacks_recipient_code_guard_or_tier_update",
                True,
            )
        )

    def test_unprovable_advisory_predicates_are_unknown_and_fail_closed(self) -> None:
        _UNKNOWN_PREDICATE_WARNED.clear()
        contract = SimpleNamespace(source_mapping=_source("contract Any {}"))
        function = _function("execute", "function execute() external { target.call(data); }")
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertFalse(
                _check_contract_pred(
                    contract,
                    "protocol.uses_presigned_refund_or_unilateral_exit",
                    True,
                )
            )
            self.assertFalse(
                _check_contract_pred(
                    contract,
                    "protocol.uses_presigned_refund_or_unilateral_exit",
                    False,
                )
            )
            self.assertFalse(_check_function_pred(function, "cfg.nonce_write_after_external_call", True))
            self.assertFalse(_check_function_pred(function, "cfg.nonce_write_after_external_call", False))
        self.assertIn("UNKNOWN contract predicate key", stderr.getvalue())
        self.assertIn("UNKNOWN function predicate key", stderr.getvalue())

    def test_contract_family_shortcuts_use_source_and_inheritance_cues(self) -> None:
        cases = [
            (
                "contract.is_balancer_linear_pool",
                "contract ERC4626LinearPool { uint256 _mainBalance; uint256 _wrappedSupply; }",
            ),
            (
                "contract.has_pool_registry",
                "contract Convert { mapping(address => bool) wells; function isValidWell(address a) public { require(wells[a]); } }",
            ),
            (
                "contract.is_price_feed_adapter",
                "contract PriceFeed { function tokenPrice() external returns (uint256) {} }",
            ),
            (
                "contract.inherits_gsn_or_access_base",
                "contract Paymaster { function isTrustedForwarder(address forwarder) public returns (bool) {} }",
            ),
            (
                "contract.has_buy_reward_or_sell_penalty",
                "contract PegToken { function applyPenalty(address from) internal {} }",
            ),
            (
                "contract.is_upgradeable_or_proxy",
                "contract DepositNFT is Initializable { function initialize() public initializer {} }",
            ),
            (
                "contract.is_lending_or_collateral_manager",
                "contract AccountContextHandler { uint16 bitmapCurrencyId; address[] activeCurrencies; }",
            ),
            (
                "contract.is_lending_market",
                "contract BaseSilo { uint256 totalBorrows; function accrueInterest() internal {} }",
            ),
            (
                "contract.is_yield_strategy_or_vault",
                "contract Strategy { uint256 poolCached; function redeem(uint256 shares) external {} }",
            ),
        ]
        for key, source in cases:
            with self.subTest(key=key):
                contract = SimpleNamespace(
                    name="Subject",
                    inheritance=[],
                    source_mapping=_source(source),
                    functions=[],
                )
                self.assertTrue(_check_contract_pred(contract, key, True))
                self.assertFalse(_check_contract_pred(contract, key, False))

    def test_family_shortcuts_ignore_comment_only_cues(self) -> None:
        comment_only = SimpleNamespace(
            name="Plain",
            inheritance=[],
            source_mapping=_source(
                """
                contract Plain {
                    // initializer tokenPrice market totalBorrows accrueInterest
                    /* isTrustedForwarder relayCall _msgSender Strategy redeem */
                    function set(uint256 x) external {}
                }
                """
            ),
            functions=[],
        )
        for key in [
            "contract.is_upgradeable_or_proxy",
            "contract.is_price_feed_adapter",
            "contract.inherits_gsn_or_access_base",
            "contract.is_lending_market",
            "contract.is_yield_strategy_or_vault",
        ]:
            with self.subTest(key=key):
                self.assertFalse(_check_contract_pred(comment_only, key, True))
                self.assertTrue(_check_contract_pred(comment_only, key, False))

    def test_family_shortcuts_ignore_string_literal_only_cues(self) -> None:
        string_only = SimpleNamespace(
            name="Plain",
            inheritance=[],
            source_mapping=_source(
                """
                contract Plain {
                    string constant TAG = "initializer isTrustedForwarder Strategy redeem totalBorrows accrueInterest";
                    function set(uint256 x) external {}
                }
                """
            ),
            functions=[],
        )
        for key in [
            "contract.is_upgradeable_or_proxy",
            "contract.inherits_gsn_or_access_base",
            "contract.is_lending_market",
            "contract.is_yield_strategy_or_vault",
        ]:
            with self.subTest(key=key):
                self.assertFalse(_check_contract_pred(string_only, key, True))
                self.assertTrue(_check_contract_pred(string_only, key, False))

    def test_accesscontrol_inheritance_is_not_gsn_or_forwarder_base(self) -> None:
        access_control = SimpleNamespace(
            name="RoleManager",
            inheritance=[SimpleNamespace(name="AccessControl")],
            source_mapping=_source("contract RoleManager is AccessControl { function setRole(bytes32 r) external {} }"),
            functions=[],
        )
        self.assertFalse(
            _check_contract_pred(access_control, "contract.inherits_gsn_or_access_base", True)
        )

    def test_contract_family_shortcuts_reject_plain_contract(self) -> None:
        plain = SimpleNamespace(
            name="Plain",
            inheritance=[],
            source_mapping=_source("contract Plain { function set(uint256 x) external {} }"),
            functions=[],
        )
        for key in [
            "contract.is_balancer_linear_pool",
            "contract.has_pool_registry",
            "contract.is_price_feed_adapter",
            "contract.inherits_gsn_or_access_base",
            "contract.has_buy_reward_or_sell_penalty",
            "contract.is_upgradeable_or_proxy",
            "contract.is_lending_or_collateral_manager",
            "contract.is_lending_market",
            "contract.is_yield_strategy_or_vault",
        ]:
            with self.subTest(key=key):
                self.assertFalse(_check_contract_pred(plain, key, True))
                self.assertTrue(_check_contract_pred(plain, key, False))

    def test_semantic_documentation_markers_fail_closed(self) -> None:
        _UNKNOWN_PREDICATE_WARNED.clear()
        function = _function("withdraw", "function withdraw() external { _withdraw(); }")
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            for key in [
                "semantic.shared_mutating_internal_helper",
                "semantic.sibling_entrypoint_has_lifecycle_or_auth_guard",
                "semantic.current_entrypoint_lacks_matching_guard",
            ]:
                with self.subTest(key=key):
                    self.assertFalse(_check_function_pred(function, key, True))
                    self.assertFalse(_check_function_pred(function, key, False))
        self.assertIn("UNKNOWN function predicate key", stderr.getvalue())

    def test_contract_has_function_without_modifier(self) -> None:
        contract = SimpleNamespace(
            functions=[
                _function("swap", "function swap() external nonReentrant {}"),
                _function("claim", "function claim() external { paid[msg.sender] = true; }"),
            ]
        )
        contract.functions[0].visibility = "external"
        contract.functions[0].modifiers = [SimpleNamespace(name="nonReentrant")]
        contract.functions[1].visibility = "external"
        contract.functions[1].modifiers = []
        self.assertTrue(_check_contract_pred(contract, "contract.has_function_without_modifier", "nonReentrant"))

        guarded = SimpleNamespace(
            functions=[
                _function("swap", "function swap() external nonReentrant {}"),
                _function("claim", "function claim() external nonReentrant {}"),
            ]
        )
        for function in guarded.functions:
            function.visibility = "external"
            function.modifiers = [SimpleNamespace(name="nonReentrant")]
        self.assertFalse(_check_contract_pred(guarded, "contract.has_function_without_modifier", "nonReentrant"))

    def test_function_is_override_uses_signature_not_comments_or_strings(self) -> None:
        overridden = _function("version", "function version() public override returns (uint256) { return 1; }")
        self.assertTrue(_check_function_pred(overridden, "function.is_override", True))

        bait = _function("version", 'function version() public returns (string memory) { return "override"; } // override')
        self.assertFalse(_check_function_pred(bait, "function.is_override", True))

    def test_body_contains_external_call_to_user_supplied_address(self) -> None:
        function = _function(
            "convert",
            """
            function convert(address well, bytes calldata data) external {
                IWell(well).lpToPeg(data);
            }
            """,
        )
        function.parameters = [SimpleNamespace(type="address", name="well")]
        self.assertTrue(
            _check_function_pred(
                function,
                "function.body_contains_external_call_to_user_supplied_addr",
                True,
            )
        )

        guarded_local = _function(
            "convert",
            "function convert(address well) external { address local = registry.defaultWell(); IWell(local).lpToPeg(); }",
        )
        guarded_local.parameters = [SimpleNamespace(type="address", name="well")]
        self.assertFalse(
            _check_function_pred(
                guarded_local,
                "function.body_contains_external_call_to_user_supplied_addr",
                True,
            )
        )

    def test_parent_contains_regex_checks_contract_context(self) -> None:
        contract = SimpleNamespace(
            name="ChildPaymaster",
            inheritance=[SimpleNamespace(name="BasePaymaster")],
            source_mapping=_source(
                """
                contract BasePaymaster { function isTrustedForwarder(address f) public returns (bool) {} }
                contract ChildPaymaster is BasePaymaster { function preRelayedCall() public override {} }
                """
            ),
            functions=[],
        )
        function = _function("preRelayedCall", "function preRelayedCall() public override {}")
        function.contract = contract
        self.assertTrue(
            _check_function_pred(function, "function.parent_contains_regex", "isTrustedForwarder")
        )

        plain_contract = SimpleNamespace(
            name="Child",
            inheritance=[],
            source_mapping=_source("contract Child { function preRelayedCall() public {} }"),
            functions=[],
        )
        plain_function = _function("preRelayedCall", "function preRelayedCall() public {}")
        plain_function.contract = plain_contract
        self.assertFalse(
            _check_function_pred(plain_function, "function.parent_contains_regex", "isTrustedForwarder")
        )

        comment_only_contract = SimpleNamespace(
            name="Child",
            inheritance=[],
            source_mapping=_source("contract Child { /* isTrustedForwarder */ function preRelayedCall() public {} }"),
            functions=[],
        )
        comment_only_function = _function("preRelayedCall", "function preRelayedCall() public {}")
        comment_only_function.contract = comment_only_contract
        self.assertFalse(
            _check_function_pred(
                comment_only_function,
                "function.parent_contains_regex",
                "isTrustedForwarder",
            )
        )

        string_only_contract = SimpleNamespace(
            name="Child",
            inheritance=[],
            source_mapping=_source('contract Child { string constant TAG = "isTrustedForwarder"; function preRelayedCall() public {} }'),
            functions=[],
        )
        string_only_function = _function("preRelayedCall", "function preRelayedCall() public {}")
        string_only_function.contract = string_only_contract
        self.assertFalse(
            _check_function_pred(
                string_only_function,
                "function.parent_contains_regex",
                "isTrustedForwarder",
            )
        )


if __name__ == "__main__":
    unittest.main()
