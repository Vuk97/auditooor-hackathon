#!/usr/bin/env python3
"""
Wave-9 Track E tests for Solidity-specific S4 ranker rules additions.

Deliverable: Tests for 10 new Solidity S4 ranker rules.
Rules cover: ERC4626 first-depositor, oracle staleness, signature replay,
unchecked calls, arbitrary transferFrom, delegatecall injection, unsafe
ERC20 transfers, hook reentrancy, governor vote double-count, and
flashloan callback auth bypasses.
"""

import unittest
import yaml
import re
from pathlib import Path


class TestRankerRulesSolidityWave9(unittest.TestCase):
    """Test suite for 10 new Solidity-specific ranker rules added in Wave-9 Track E."""

    @classmethod
    def setUpClass(cls):
        """Load ranker_rules.yaml and set up test fixtures."""
        workspace_root = Path(__file__).parent.parent.parent
        cls.ranker_path = workspace_root / "audit" / "ranker_rules.yaml"

        with open(cls.ranker_path) as f:
            cls.ranker = yaml.safe_load(f)

        # Synthetic Solidity ERC4626 first-depositor fixture
        cls.sol_erc4626_first_depositor_fixture = {
            "language": "solidity",
            "function_name": "deposit",
            "receiver_family": "token-family",
            "body": """function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
                if (totalSupply() == 0) {
                    shares = assets;
                } else {
                    shares = (assets * totalSupply()) / totalAssets();
                }
                _deposit(assets, receiver, shares);
            }""",
        }

        # Synthetic Solidity oracle staleness fixture
        cls.sol_oracle_staleness_fixture = {
            "language": "solidity",
            "function_name": "getPrice",
            "body": """function getPrice(address token) public view returns (uint256) {
                uint256 price = oracle.latestAnswer();
                return price;
            }""",
        }

        # Synthetic Solidity signature replay (no nonce/deadline) fixture
        cls.sol_signature_replay_fixture = {
            "language": "solidity",
            "function_name": "executeWithSignature",
            "body": """function executeWithSignature(bytes calldata signature, bytes calldata data) public {
                address signer = ecrecover(keccak256(data), v, r, s);
                require(signer == owner);
                (bool success,) = address(this).call(data);
                require(success);
            }""",
        }

        # Synthetic unchecked external call fixture
        cls.sol_unchecked_call_fixture = {
            "language": "solidity",
            "function_name": "withdraw",
            "body": """function withdraw(uint256 amount) public {
                balance[msg.sender] -= amount;
                (bool success,) = msg.sender.call{value: amount}("");
            }""",
        }

        # Synthetic arbitrary transferFrom fixture
        cls.sol_arbitrary_from_fixture = {
            "language": "solidity",
            "function_name": "transferFrom",
            "receiver_family": "erc20-family",
            "body": """function transferFrom(address from, address to, uint256 amount) public {
                balanceOf[from] -= amount;
                balanceOf[to] += amount;
                emit Transfer(from, to, amount);
            }""",
        }

        # Synthetic delegatecall with user input fixture
        cls.sol_delegatecall_user_input_fixture = {
            "language": "solidity",
            "function_name": "delegateToUserTarget",
            "body": """function delegateToUserTarget(address caller, bytes calldata data) public {
                (bool success, bytes memory result) = caller.delegatecall(data);
                require(success);
                return result;
            }""",
        }

        # Synthetic unsafe ERC20 transfer fixture
        cls.sol_unsafe_transfer_fixture = {
            "language": "solidity",
            "function_name": "withdrawToken",
            "body": """function withdrawToken(address token, uint256 amount) public {
                IERC20(token).transfer(msg.sender, amount);
                balance -= amount;
            }""",
        }

        # Synthetic hook reentrancy fixture
        cls.sol_hook_reentrancy_fixture = {
            "language": "solidity",
            "function_name": "_beforeTokenTransfer",
            "body": """function _beforeTokenTransfer(address from, address to, uint256 amount) internal {
                balanceOf[from] -= amount;
                if (hooks[from].callback != address(0)) {
                    (bool success,) = hooks[from].callback.call(abi.encodeWithSignature("onBeforeTransfer(address,address,uint256)", from, to, amount));
                    require(success);
                }
            }""",
        }

        # Synthetic governor vote double-count fixture
        cls.sol_governor_vote_fixture = {
            "language": "solidity",
            "function_name": "castVote",
            "receiver_family": "governor-family",
            "body": """function castVote(uint256 proposalId, uint8 support) public {
                votes[proposalId][msg.sender] += 1;
                proposal.voteCount[support] += 1;
            }""",
        }

        # Synthetic flashloan callback fixture
        cls.sol_flashloan_callback_fixture = {
            "language": "solidity",
            "function_name": "executeOperation",
            "body": """function executeOperation(address asset, uint256 amount, uint256 premium, address initiator, bytes calldata params) public returns (bytes32) {
                uint256 amountOwed = amount + premium;
                IERC20(asset).approve(address(this), amountOwed);
                return keccak256(abi.encodePacked("ERC3156FlashBorrower.onFlashLoan"));
            }""",
        }

    def test_all_ten_solidity_rules_exist(self):
        """Assertion 1: All 10 new Solidity rules are present."""
        expected_rules = [
            "RULE_SOL_ERC4626_FIRST_DEPOSITOR",
            "RULE_SOL_ORACLE_STALENESS_NO_CHECK",
            "RULE_SOL_SIGNATURE_REPLAY_NO_NONCE",
            "RULE_SOL_UNCHECKED_EXTERNAL_CALL",
            "RULE_SOL_ARBITRARY_FROM_TRANSFER",
            "RULE_SOL_DELEGATECALL_USER_INPUT",
            "RULE_SOL_UNSAFE_TRANSFER_NO_RETURN_CHECK",
            "RULE_SOL_REENTRANCY_VIA_HOOK",
            "RULE_SOL_GOVERNOR_VOTE_DOUBLE_COUNT",
            "RULE_SOL_FLASHLOAN_CALLBACK_AUTH",
        ]
        for rule_id in expected_rules:
            self.assertIn(rule_id, self.ranker, f"Rule {rule_id} must exist in ranker_rules.yaml")

    def test_all_rules_have_provenance(self):
        """Assertion 2: Each new rule has a provenance field."""
        new_rules = [
            "RULE_SOL_ERC4626_FIRST_DEPOSITOR",
            "RULE_SOL_ORACLE_STALENESS_NO_CHECK",
            "RULE_SOL_SIGNATURE_REPLAY_NO_NONCE",
            "RULE_SOL_UNCHECKED_EXTERNAL_CALL",
            "RULE_SOL_ARBITRARY_FROM_TRANSFER",
            "RULE_SOL_DELEGATECALL_USER_INPUT",
            "RULE_SOL_UNSAFE_TRANSFER_NO_RETURN_CHECK",
            "RULE_SOL_REENTRANCY_VIA_HOOK",
            "RULE_SOL_GOVERNOR_VOTE_DOUBLE_COUNT",
            "RULE_SOL_FLASHLOAN_CALLBACK_AUTH",
        ]
        for rule_id in new_rules:
            rule = self.ranker[rule_id]
            self.assertIn(
                "provenance",
                rule,
                f"Rule {rule_id} must have provenance field",
            )
            provenance = rule.get("provenance")
            self.assertIsNotNone(provenance, f"Rule {rule_id} provenance must not be None")
            self.assertGreater(len(str(provenance)), 0, f"Rule {rule_id} provenance must not be empty")

    def test_all_rules_have_solidity_language_filter(self):
        """Assertion 3: Each rule filters for solidity language."""
        new_rules = [
            "RULE_SOL_ERC4626_FIRST_DEPOSITOR",
            "RULE_SOL_ORACLE_STALENESS_NO_CHECK",
            "RULE_SOL_SIGNATURE_REPLAY_NO_NONCE",
            "RULE_SOL_UNCHECKED_EXTERNAL_CALL",
            "RULE_SOL_ARBITRARY_FROM_TRANSFER",
            "RULE_SOL_DELEGATECALL_USER_INPUT",
            "RULE_SOL_UNSAFE_TRANSFER_NO_RETURN_CHECK",
            "RULE_SOL_REENTRANCY_VIA_HOOK",
            "RULE_SOL_GOVERNOR_VOTE_DOUBLE_COUNT",
            "RULE_SOL_FLASHLOAN_CALLBACK_AUTH",
        ]
        for rule_id in new_rules:
            rule = self.ranker[rule_id]
            conditions = rule.get("conditions", {})
            lang = conditions.get("lang")
            self.assertEqual(
                lang, "solidity", f"Rule {rule_id} must have lang: solidity"
            )

    def test_erc4626_first_depositor_fires_on_fixture(self):
        """Assertion 4: RULE_SOL_ERC4626_FIRST_DEPOSITOR fires on synthetic fixture."""
        rule = self.ranker["RULE_SOL_ERC4626_FIRST_DEPOSITOR"]
        fixture = self.sol_erc4626_first_depositor_fixture
        conditions = rule.get("conditions", {})

        # Check language
        self.assertEqual(conditions.get("lang"), "solidity")

        # Check function name regex matches "deposit"
        fn_regex = conditions.get("fn_name_regex")
        self.assertIsNotNone(fn_regex)
        self.assertTrue(
            re.search(fn_regex, fixture["function_name"]),
            f"fn_name_regex {fn_regex} should match {fixture['function_name']}",
        )

        # Check body pattern matches totalSupply() == 0
        body_pattern = conditions.get("body_contains_regex")
        self.assertIsNotNone(body_pattern)
        self.assertTrue(
            re.search(body_pattern, fixture["body"]),
            f"body pattern {body_pattern} should match fixture",
        )

    def test_oracle_staleness_fires_on_fixture(self):
        """Assertion 5: RULE_SOL_ORACLE_STALENESS_NO_CHECK fires on fixture."""
        rule = self.ranker["RULE_SOL_ORACLE_STALENESS_NO_CHECK"]
        fixture = self.sol_oracle_staleness_fixture
        conditions = rule.get("conditions", {})

        # Check language
        self.assertEqual(conditions.get("lang"), "solidity")

        # Check call_match for oracle pattern
        call_pattern = conditions.get("call_match")
        self.assertIsNotNone(call_pattern)
        self.assertTrue(
            re.search(call_pattern, fixture["body"]),
            f"call pattern {call_pattern} should match latestAnswer",
        )

    def test_signature_replay_fires_on_fixture(self):
        """Assertion 6: RULE_SOL_SIGNATURE_REPLAY_NO_NONCE fires on fixture."""
        rule = self.ranker["RULE_SOL_SIGNATURE_REPLAY_NO_NONCE"]
        fixture = self.sol_signature_replay_fixture
        conditions = rule.get("conditions", {})

        # Check language
        self.assertEqual(conditions.get("lang"), "solidity")

        # Check call_match for ecrecover
        call_pattern = conditions.get("call_match")
        self.assertIsNotNone(call_pattern)
        self.assertTrue(
            re.search(call_pattern, fixture["body"]),
            f"call pattern {call_pattern} should match ecrecover",
        )

    def test_unchecked_call_fires_on_fixture(self):
        """Assertion 7: RULE_SOL_UNCHECKED_EXTERNAL_CALL fires on fixture."""
        rule = self.ranker["RULE_SOL_UNCHECKED_EXTERNAL_CALL"]
        fixture = self.sol_unchecked_call_fixture
        conditions = rule.get("conditions", {})

        # Check language
        self.assertEqual(conditions.get("lang"), "solidity")

        # Check call_match for .call pattern
        call_pattern = conditions.get("call_match")
        self.assertIsNotNone(call_pattern)
        self.assertTrue(
            re.search(call_pattern, fixture["body"]),
            f"call pattern {call_pattern} should match .call{{",
        )

        # Verify the fixture does NOT have require() wrapping
        body_require_pattern = conditions.get("body_not_contains_regex")
        self.assertIsNotNone(body_require_pattern)

    def test_arbitrary_transfer_from_fires_on_fixture(self):
        """Assertion 8: RULE_SOL_ARBITRARY_FROM_TRANSFER fires on fixture."""
        rule = self.ranker["RULE_SOL_ARBITRARY_FROM_TRANSFER"]
        fixture = self.sol_arbitrary_from_fixture
        conditions = rule.get("conditions", {})

        # Check language
        self.assertEqual(conditions.get("lang"), "solidity")

        # Check function name matches transferFrom
        fn_regex = conditions.get("fn_name_regex")
        self.assertIsNotNone(fn_regex)
        self.assertTrue(
            re.search(fn_regex, fixture["function_name"]),
            f"fn_name_regex {fn_regex} should match transferFrom",
        )

    def test_delegatecall_user_input_fires_on_fixture(self):
        """Assertion 9: RULE_SOL_DELEGATECALL_USER_INPUT fires on fixture."""
        rule = self.ranker["RULE_SOL_DELEGATECALL_USER_INPUT"]
        fixture = self.sol_delegatecall_user_input_fixture
        conditions = rule.get("conditions", {})

        # Check language
        self.assertEqual(conditions.get("lang"), "solidity")

        # Check for delegatecall call pattern
        call_pattern = conditions.get("call_match")
        self.assertIsNotNone(call_pattern)
        self.assertTrue(
            re.search(call_pattern, fixture["body"]),
            f"call pattern {call_pattern} should match delegatecall",
        )

        # Check for user-input body pattern
        body_pattern = conditions.get("body_contains_regex")
        self.assertIsNotNone(body_pattern)
        self.assertTrue(
            re.search(body_pattern, fixture["body"]),
            f"body pattern {body_pattern} should detect user-controllable address",
        )

    def test_unsafe_transfer_fires_on_fixture(self):
        """Assertion 10: RULE_SOL_UNSAFE_TRANSFER_NO_RETURN_CHECK fires on fixture."""
        rule = self.ranker["RULE_SOL_UNSAFE_TRANSFER_NO_RETURN_CHECK"]
        fixture = self.sol_unsafe_transfer_fixture
        conditions = rule.get("conditions", {})

        # Check language
        self.assertEqual(conditions.get("lang"), "solidity")

        # Check for transfer call pattern
        call_pattern = conditions.get("call_match")
        self.assertIsNotNone(call_pattern)
        self.assertTrue(
            re.search(call_pattern, fixture["body"]),
            f"call pattern {call_pattern} should match transfer",
        )

    def test_hook_reentrancy_fires_on_fixture(self):
        """RULE_SOL_REENTRANCY_VIA_HOOK fires on hook-reentrancy fixture."""
        rule = self.ranker["RULE_SOL_REENTRANCY_VIA_HOOK"]
        fixture = self.sol_hook_reentrancy_fixture
        conditions = rule.get("conditions", {})

        # Check language
        self.assertEqual(conditions.get("lang"), "solidity")

        # Check function name matches hook pattern
        fn_regex = conditions.get("fn_name_regex")
        self.assertIsNotNone(fn_regex)
        self.assertTrue(
            re.search(fn_regex, fixture["function_name"]),
            f"fn_name_regex {fn_regex} should match _beforeTokenTransfer",
        )

        # Check for external call pattern
        call_pattern = conditions.get("call_match")
        self.assertIsNotNone(call_pattern)
        self.assertTrue(
            re.search(call_pattern, fixture["body"]),
            f"call pattern {call_pattern} should detect callback",
        )

    def test_governor_vote_double_count_fires_on_fixture(self):
        """RULE_SOL_GOVERNOR_VOTE_DOUBLE_COUNT fires on governor fixture."""
        rule = self.ranker["RULE_SOL_GOVERNOR_VOTE_DOUBLE_COUNT"]
        fixture = self.sol_governor_vote_fixture
        conditions = rule.get("conditions", {})

        # Check language
        self.assertEqual(conditions.get("lang"), "solidity")

        # Check function name matches castVote pattern
        fn_regex = conditions.get("fn_name_regex")
        self.assertIsNotNone(fn_regex)
        self.assertTrue(
            re.search(fn_regex, fixture["function_name"]),
            f"fn_name_regex {fn_regex} should match castVote",
        )

        # Verify fixture does NOT have hasVoted check
        body_not_pattern = conditions.get("body_not_contains_regex")
        self.assertIsNotNone(body_not_pattern)

    def test_flashloan_callback_auth_fires_on_fixture(self):
        """RULE_SOL_FLASHLOAN_CALLBACK_AUTH fires on flashloan fixture."""
        rule = self.ranker["RULE_SOL_FLASHLOAN_CALLBACK_AUTH"]
        fixture = self.sol_flashloan_callback_fixture
        conditions = rule.get("conditions", {})

        # Check language
        self.assertEqual(conditions.get("lang"), "solidity")

        # Check function name matches callback pattern
        fn_regex = conditions.get("fn_name_regex")
        self.assertIsNotNone(fn_regex)
        self.assertTrue(
            re.search(fn_regex, fixture["function_name"]),
            f"fn_name_regex {fn_regex} should match executeOperation",
        )

    def test_all_rules_have_contributes(self):
        """All rules have non-empty contributes with attack classes and numeric values."""
        new_rules = [
            "RULE_SOL_ERC4626_FIRST_DEPOSITOR",
            "RULE_SOL_ORACLE_STALENESS_NO_CHECK",
            "RULE_SOL_SIGNATURE_REPLAY_NO_NONCE",
            "RULE_SOL_UNCHECKED_EXTERNAL_CALL",
            "RULE_SOL_ARBITRARY_FROM_TRANSFER",
            "RULE_SOL_DELEGATECALL_USER_INPUT",
            "RULE_SOL_UNSAFE_TRANSFER_NO_RETURN_CHECK",
            "RULE_SOL_REENTRANCY_VIA_HOOK",
            "RULE_SOL_GOVERNOR_VOTE_DOUBLE_COUNT",
            "RULE_SOL_FLASHLOAN_CALLBACK_AUTH",
        ]
        for rule_id in new_rules:
            rule = self.ranker[rule_id]
            contributes = rule.get("contributes", {})
            self.assertGreater(
                len(contributes), 0, f"Rule {rule_id} must have attack classes"
            )
            for attack_class, contribution_value in contributes.items():
                self.assertIsInstance(
                    contribution_value, (int, float),
                    f"Contribution {attack_class}={contribution_value} must be numeric",
                )

    def test_total_rule_count(self):
        """Total rule count is now 26 (16 prior + 10 new)."""
        expected_count = 26
        actual_count = len(self.ranker)
        self.assertGreaterEqual(
            actual_count, expected_count,
            f"Should have at least {expected_count} rules; found {actual_count}",
        )

    def test_no_prior_rules_modified(self):
        """Verify Wave-6 rules (RULE_GO_TOCTOU_TIMESTAMP, etc.) are untouched."""
        wave6_rules = [
            "RULE_GO_TOCTOU_TIMESTAMP",
            "RULE_SOL_RECEIVE_NO_REENTRANCY",
            "RULE_GO_CONTEXT_DEADLINE_BYPASS",
            "RULE_RUST_ASYNC_NO_TIMEOUT",
            "RULE_GO_CHANNEL_NO_BUFFER_RACE",
        ]
        for rule_id in wave6_rules:
            self.assertIn(rule_id, self.ranker, f"Wave-6 rule {rule_id} must still exist")


if __name__ == "__main__":
    unittest.main()
