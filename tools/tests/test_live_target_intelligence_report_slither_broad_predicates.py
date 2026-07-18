#!/usr/bin/env python3
"""Focused fake-Slither tests for broader P1 predicate wiring."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent.parent

_LTIR_PATH = _ROOT / "tools" / "live-target-intelligence-report.py"
_LTIR_SPEC = importlib.util.spec_from_file_location(
    "live_target_intelligence_report_slither_broad_predicates",
    _LTIR_PATH,
)
ltir_mod = importlib.util.module_from_spec(_LTIR_SPEC)
assert _LTIR_SPEC.loader is not None
_LTIR_SPEC.loader.exec_module(ltir_mod)

_SLITHER_PATH = _ROOT / "tools" / "slither_predicates.py"
_SLITHER_SPEC = importlib.util.spec_from_file_location(
    "slither_predicates_for_broad_predicate_tests",
    _SLITHER_PATH,
)
slither_mod = importlib.util.module_from_spec(_SLITHER_SPEC)
assert _SLITHER_SPEC.loader is not None
_SLITHER_SPEC.loader.exec_module(slither_mod)


class _FakeNode(SimpleNamespace):
    def __init__(self, expression: str = "", **kwargs: object) -> None:
        super().__init__(expression=expression, **kwargs)


class _FakeFunction:
    def __init__(self, nodes: list[object], source: str) -> None:
        self.nodes = nodes
        self.source_mapping = SimpleNamespace(content=source)


class _FakeSlitherModule:
    def __init__(self, labels: dict[str, bool], calls: list[str]) -> None:
        self.labels = labels
        self.calls = calls

    def check(self, function: object, label: str) -> bool:
        del function
        self.calls.append(label)
        return self.labels.get(label, False)


class LiveTargetSlitherBroadPredicateTests(unittest.TestCase):
    def test_helper_dispatch_consumes_ast_labels_without_real_slither(self) -> None:
        fn = _FakeFunction(
            [
                _FakeNode(
                    solidity_variables_read=[SimpleNamespace(name="msg.sender")],
                    low_level_calls=[("recipient", "delegatecall")],
                    solidity_calls=[SimpleNamespace(name="keccak256"), SimpleNamespace(name="abi.encodePacked")],
                )
            ],
            source="function demo() external { require(msg.sender != address(0)); }",
        )

        self.assertTrue(slither_mod.available(fn))
        self.assertTrue(slither_mod.check(fn, "reads_msg_sender"))
        self.assertTrue(slither_mod.check(fn, "has_low_level_delegatecall"))
        self.assertTrue(slither_mod.check(fn, "computes_keccak"))
        self.assertTrue(slither_mod.check(fn, "computes_abi_encode"))
        self.assertFalse(slither_mod.check(fn, "reads_tx_origin"))

    def test_helper_dispatch_stays_ast_first_when_source_text_mentions_label(self) -> None:
        fn = _FakeFunction(
            [
                _FakeNode(
                    solidity_variables_read=[],
                    low_level_calls=[],
                    solidity_calls=[],
                )
            ],
            source='function demo() external { string memory hint = "msg.sender"; }',
        )

        self.assertTrue(slither_mod.available(fn))
        self.assertFalse(slither_mod.check(fn, "reads_msg_sender"))

    def test_auth_001_should_consume_slither_owner_label_before_textual_only_owner(self) -> None:
        source = """
        contract Vault is UUPSUpgradeable {
          function _authorizeUpgrade(address newImpl) internal override onlyOwner {
            newImpl;
          }
        }
        """
        fake_calls: list[str] = []
        fake_module = _FakeSlitherModule({"has_only_owner_modifier": False}, fake_calls)

        with mock.patch.object(ltir_mod, "_load_slither_predicates_module", return_value=fake_module):
            self.assertTrue(ltir_mod._p1_predicate_auth_001(source, ""))

        self.assertEqual(fake_calls, ["has_only_owner_modifier"])

    def test_uni_002_consumes_ecrecover_label_before_textual_signature(self) -> None:
        source = """
        contract PermitLike {
          bytes32 public DOMAIN_SEPARATOR;
          function permit(bytes32 digest, uint8 v, bytes32 r, bytes32 s) external {
            address signer = ecrecover(digest, v, r, s);
            signer;
          }
        }
        """
        fake_calls: list[str] = []
        fake_module = _FakeSlitherModule({"calls_ecrecover": True}, fake_calls)

        with mock.patch.object(ltir_mod, "_load_slither_predicates_module", return_value=fake_module):
            self.assertTrue(ltir_mod._p1_predicate_uni_002(source, ""))

        self.assertEqual(fake_calls, ["calls_ecrecover"])

    def test_bridge_003_slither_consumes_all_call_shape_helper_labels(self) -> None:
        source = """
        contract BridgePayout {
          mapping(bytes32 => bool) public commitments;
          function execute(bytes32 commitment, address payable to, bytes calldata data) external {
            (bool ok,) = to.call{value: 1 ether}(data);
            commitments[commitment] = false;
            ok;
          }
        }
        """
        fake_calls: list[str] = []
        fake_module = _FakeSlitherModule(
            {
                "has_low_level_call": False,
                "has_safe_transfer": False,
                "has_transfer_from": True,
            },
            fake_calls,
        )
        fake_function = _FakeFunction(
            [
                _FakeNode("(bool ok,) = to.call{value: 1 ether}(data)", low_level_calls=[("to", "call")]),
                _FakeNode(
                    "commitments[commitment] = false",
                    state_variables_written=[SimpleNamespace(name="commitments")],
                ),
            ],
            source=source,
        )

        with mock.patch.object(ltir_mod, "_load_slither_predicates_module", return_value=fake_module):
            self.assertTrue(ltir_mod._slither_bridge_003_function_violation(fake_function))

        self.assertEqual(
            fake_calls,
            [
                "has_low_level_call",
                "has_low_level_delegatecall",
                "has_safe_transfer",
                "has_transfer_from",
                "has_non_reentrant_modifier",
            ],
        )

    def test_bridge_005_slither_consumes_block_clock_helper_labels(self) -> None:
        source = """
        contract LightClient {
          uint256 constant FRESHNESS_WINDOW = 1024;
          struct Proof { uint256 height; bytes proof; }
          function acceptState(bytes32 root, Proof calldata finalityProof) external {
            require(finalityProof.height < FRESHNESS_WINDOW, "stale");
            root;
          }
        }
        """
        fake_calls: list[str] = []
        fake_module = _FakeSlitherModule(
            {
                "reads_block_number": False,
                "reads_block_timestamp": True,
            },
            fake_calls,
        )
        fake_function = _FakeFunction(
            [_FakeNode('require(finalityProof.height < FRESHNESS_WINDOW, "stale")')],
            source=source,
        )

        with mock.patch.object(ltir_mod, "_load_slither_predicates_module", return_value=fake_module):
            with mock.patch.object(
                ltir_mod,
                "_slither_candidate_functions_for_predicate",
                return_value=[fake_function],
            ):
                self.assertFalse(ltir_mod._p1_predicate_bridge_005_slither(source))

        self.assertEqual(fake_calls, ["reads_block_number", "reads_block_timestamp"])

    def test_bridge_006_slither_consumes_abi_encode_for_replay_digest(self) -> None:
        source = """
        contract BridgeVerifier {
          function verifyBridgeProof(
            uint32 sourceDomain,
            uint32 destinationDomain,
            bytes32 leaf,
            bytes32 root,
            uint256 nonce,
            bytes calldata proof,
            bytes32 payloadHash
          ) external {
            bytes32 replayKey = keccak256(abi.encode(leaf, root, nonce, payloadHash));
            sourceDomain; destinationDomain; proof; replayKey;
          }
        }
        """
        fake_calls: list[str] = []
        fake_module = _FakeSlitherModule(
            {
                "computes_abi_encode": True,
                "computes_keccak": True,
            },
            fake_calls,
        )
        fake_function = _FakeFunction(
            [_FakeNode("bytes32 replayKey = keccak256(abi.encode(leaf, root, nonce, payloadHash))")],
            source=source,
        )
        fake_function.visibility = "external"

        with mock.patch.object(ltir_mod, "_load_slither_predicates_module", return_value=fake_module):
            with mock.patch.object(
                ltir_mod,
                "_slither_candidate_functions_for_predicate",
                return_value=[fake_function],
            ):
                self.assertTrue(ltir_mod._p1_predicate_bridge_006(source, ""))

        self.assertEqual(fake_calls, ["computes_abi_encode", "computes_keccak"])

    def test_bridge_006_slither_does_not_fallback_to_unrelated_helper_abi_encode(self) -> None:
        source = """
        contract BridgeVerifier {
          function verifyBridgeProof(
            uint32 sourceDomain,
            uint32 destinationDomain,
            bytes32 leaf,
            bytes32 root,
            uint256 nonce,
            bytes calldata proof
          ) external {
            sourceDomain; destinationDomain; leaf; root; nonce; proof;
          }

          function _helperReplayDigest(bytes32 leaf, bytes32 root, uint256 nonce) internal pure returns (bytes32) {
            return keccak256(abi.encode(leaf, root, nonce));
          }
        }
        """
        fake_calls: list[str] = []
        fake_module = _FakeSlitherModule({"computes_abi_encode": False}, fake_calls)
        fake_function = _FakeFunction(
            [_FakeNode("sourceDomain; destinationDomain; leaf; root; nonce; proof;")],
            source="""
            function verifyBridgeProof(
              uint32 sourceDomain,
              uint32 destinationDomain,
              bytes32 leaf,
              bytes32 root,
              uint256 nonce,
              bytes calldata proof
            ) external {
              sourceDomain; destinationDomain; leaf; root; nonce; proof;
            }
            """,
        )
        fake_function.visibility = "external"

        with mock.patch.object(ltir_mod, "_load_slither_predicates_module", return_value=fake_module):
            with mock.patch.object(
                ltir_mod,
                "_slither_candidate_functions_for_predicate",
                return_value=[fake_function],
            ):
                self.assertFalse(ltir_mod._p1_predicate_bridge_006(source, ""))

        self.assertEqual(fake_calls, ["computes_abi_encode"])
        self.assertTrue(
            slither_mod.regex_fallback(
                _FakeFunction([], "function _helperReplayDigest() internal { return keccak256(abi.encode(leaf, root, nonce)); }"),
                "computes_abi_encode",
            )
        )

    def test_bridge_006_slither_accepts_digest_with_both_domains_bound(self) -> None:
        source = """
        contract BridgeVerifier {
          function verifyBridgeProof(
            uint32 sourceDomain,
            uint32 destinationDomain,
            bytes32 leaf,
            bytes32 root,
            uint256 nonce,
            bytes calldata proof
          ) external {
            bytes32 replayKey = keccak256(abi.encode(sourceDomain, destinationDomain, leaf, root, nonce));
            proof; replayKey;
          }
        }
        """
        fake_calls: list[str] = []
        fake_module = _FakeSlitherModule(
            {
                "computes_abi_encode": True,
                "computes_keccak": True,
            },
            fake_calls,
        )
        fake_function = _FakeFunction(
            [_FakeNode("bytes32 replayKey = keccak256(abi.encode(sourceDomain, destinationDomain, leaf, root, nonce))")],
            source=source,
        )
        fake_function.visibility = "external"

        with mock.patch.object(ltir_mod, "_load_slither_predicates_module", return_value=fake_module):
            with mock.patch.object(
                ltir_mod,
                "_slither_candidate_functions_for_predicate",
                return_value=[fake_function],
            ):
                self.assertFalse(ltir_mod._p1_predicate_bridge_006(source, ""))

        self.assertEqual(fake_calls, ["computes_abi_encode", "computes_keccak"])

    def test_bridge_006_slither_ignores_unrelated_digest_when_domains_are_parameters(self) -> None:
        source = """
        contract BridgeVerifier {
          function verifyBridgeProof(
            uint32 sourceDomain,
            uint32 destinationDomain,
            address user,
            uint256 amount,
            uint256 nonce,
            bytes calldata proof
          ) external {
            bytes32 paymentKey = keccak256(abi.encode(user, amount, nonce));
            sourceDomain; destinationDomain; proof; paymentKey;
          }
        }
        """
        fake_calls: list[str] = []
        fake_module = _FakeSlitherModule(
            {
                "computes_abi_encode": True,
                "computes_keccak": True,
            },
            fake_calls,
        )
        fake_function = _FakeFunction(
            [_FakeNode("bytes32 paymentKey = keccak256(abi.encode(user, amount, nonce))")],
            source=source,
        )
        fake_function.visibility = "external"

        with mock.patch.object(ltir_mod, "_load_slither_predicates_module", return_value=fake_module):
            with mock.patch.object(
                ltir_mod,
                "_slither_candidate_functions_for_predicate",
                return_value=[fake_function],
            ):
                self.assertFalse(ltir_mod._p1_predicate_bridge_006(source, ""))

        self.assertEqual(fake_calls, ["computes_abi_encode", "computes_keccak"])

    def test_auth_006_slither_consumes_calls_selfdestruct_helper(self) -> None:
        source = """
        contract EmergencyStop {
          function destroyFunds() external {
            uint256 marker = 1;
            marker;
          }
        }
        """
        fake_calls: list[str] = []
        fake_module = _FakeSlitherModule({"calls_selfdestruct": True}, fake_calls)
        fake_function = _FakeFunction([_FakeNode("uint256 marker = 1")], source=source)

        with mock.patch.object(ltir_mod, "_load_slither_predicates_module", return_value=fake_module):
            with mock.patch.object(
                ltir_mod,
                "_slither_candidate_functions_for_predicate",
                return_value=[fake_function],
            ):
                self.assertTrue(ltir_mod._p1_predicate_auth_006(source, ""))

        self.assertEqual(fake_calls, ["calls_selfdestruct"])

    def test_defi_003_slither_consumes_latest_round_data_helper(self) -> None:
        source = """
        contract OracleReader {
          function getPrice() external view returns (uint256) {
            return 1;
          }
        }
        """
        fake_calls: list[str] = []
        fake_module = _FakeSlitherModule({"has_latest_round_data": True}, fake_calls)
        fake_function = _FakeFunction([_FakeNode("return 1")], source=source)

        with mock.patch.object(ltir_mod, "_load_slither_predicates_module", return_value=fake_module):
            with mock.patch.object(
                ltir_mod,
                "_slither_candidate_functions_for_predicate",
                return_value=[fake_function],
            ):
                self.assertTrue(ltir_mod._p1_predicate_defi_003(source, ""))

        self.assertEqual(fake_calls, ["has_latest_round_data"])

    def test_auth_001_revert_guard_consumes_has_revert_helper(self) -> None:
        source = """
        contract Vault is UUPSUpgradeable {
          address owner;
          function _authorizeUpgrade(address newImpl) internal override {
            if (msg.sender != owner) revert Unauthorized();
            newImpl;
          }
        }
        """
        fake_calls: list[str] = []
        fake_module = _FakeSlitherModule(
            {"has_only_owner_modifier": False, "has_revert": True},
            fake_calls,
        )

        with mock.patch.object(ltir_mod, "_load_slither_predicates_module", return_value=fake_module):
            self.assertFalse(ltir_mod._p1_predicate_auth_001(source, ""))

        self.assertEqual(fake_calls, ["has_only_owner_modifier", "has_revert"])


if __name__ == "__main__":
    unittest.main()
