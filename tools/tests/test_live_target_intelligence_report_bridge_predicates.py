#!/usr/bin/env python3
"""Focused cross-chain bridge CAP-021 predicate tests."""

from __future__ import annotations

import importlib.util
import unittest
from unittest import mock
from pathlib import Path


_HERE = Path(__file__).resolve().parent
_TOOL_PATH = _HERE.parent / "live-target-intelligence-report.py"
_spec = importlib.util.spec_from_file_location(
    "live_target_intelligence_report_bridge_predicates", _TOOL_PATH
)
ltir_mod = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(ltir_mod)


class _FakeStateVar:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakeModifier:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakeSolidityCall:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakeSourceMapping:
    def __init__(self, content: str) -> None:
        self.content = content


class _FakeNode:
    def __init__(
        self,
        expression: str,
        *,
        reads: tuple[str, ...] = (),
        writes: tuple[str, ...] = (),
        solidity_reads: tuple[str, ...] = (),
        solidity_calls: tuple[str, ...] = (),
        low_level_call: bool = False,
    ) -> None:
        self.expression = expression
        self.state_variables_read = [_FakeStateVar(name) for name in reads]
        self.state_variables_written = [_FakeStateVar(name) for name in writes]
        self.solidity_variables_read = [_FakeStateVar(name) for name in solidity_reads]
        self.solidity_calls = [_FakeSolidityCall(name) for name in solidity_calls]
        self.low_level_calls = ["call"] if low_level_call else []
        self.high_level_calls = []
        self.irs = []


class _FakeFunction:
    def __init__(
        self,
        nodes: list[_FakeNode],
        *,
        source: str = "",
        name: str = "execute",
        visibility: str = "external",
        modifiers: tuple[str, ...] = (),
    ) -> None:
        self.nodes = nodes
        self.name = name
        self.visibility = visibility
        self.modifiers = [_FakeModifier(name) for name in modifiers]
        self.source_mapping = _FakeSourceMapping(source)


class Cap021BridgePredicateMatchTest(unittest.TestCase):
    def _semantic(self, inv_id: str, source: str) -> list[str]:
        return ltir_mod._semantic_p1_matches(
            "cap021-bridge-direct",
            matched_p1=[inv_id],
            file_line="src/Bridge.sol:1",
            snippet="",
            source_context=source,
            source_contract_context=source,
        )

    def test_bridge_001_inbound_handler_requires_caller_auth(self) -> None:
        tp = """
        contract BridgeReceiver {
          function onAccept(bytes calldata message, uint256 nonce, uint256 sourceChain) external {
            _execute(message, nonce, sourceChain);
          }
        }
        """
        fp = """
        contract BridgeReceiver {
          address public host;
          function onAccept(bytes calldata message, uint256 nonce, uint256 sourceChain) external {
            require(msg.sender == host, "host only");
            _execute(message, nonce, sourceChain);
          }
        }
        """
        self.assertEqual(self._semantic("INV-BRIDGE-001", tp), ["INV-BRIDGE-001"])
        self.assertEqual(self._semantic("INV-BRIDGE-001", fp), [])

    def test_bridge_001_slither_ir_suppresses_restricted_modifier_false_positive(self) -> None:
        source = """
        contract BridgeReceiver {
          function onAccept(bytes calldata message, uint256 nonce, uint256 sourceChain) external restricted {
            _execute(message, nonce, sourceChain);
          }
        }
        """
        ir_safe = _FakeFunction(
            [_FakeNode("_execute(message, nonce, sourceChain)")],
            source=source,
            name="onAccept",
            modifiers=("restricted",),
        )
        with mock.patch.object(
            ltir_mod,
            "_slither_candidate_functions_for_predicate",
            return_value=[ir_safe],
        ):
            self.assertEqual(self._semantic("INV-BRIDGE-001", source), [])

    def test_bridge_001_regex_fallback_still_flags_missing_caller_auth(self) -> None:
        source = """
        contract BridgeReceiver {
          function onAccept(bytes calldata message, uint256 nonce, uint256 sourceChain) external {
            _execute(message, nonce, sourceChain);
          }
        }
        """
        with mock.patch.object(ltir_mod, "_p1_predicate_bridge_001_slither", return_value=None):
            self.assertEqual(self._semantic("INV-BRIDGE-001", source), ["INV-BRIDGE-001"])

    def test_bridge_002_state_machine_registration_requires_authority(self) -> None:
        tp = """
        contract Registry {
          mapping(uint256 => address) public clients;
          function registerStateMachine(uint256 chainId, address client) external {
            clients[chainId] = client;
          }
        }
        """
        fp = """
        contract Registry {
          mapping(uint256 => address) public clients;
          function registerStateMachine(uint256 chainId, address client) external onlyGovernance {
            clients[chainId] = client;
          }
        }
        """
        self.assertEqual(self._semantic("INV-BRIDGE-002", tp), ["INV-BRIDGE-002"])
        self.assertEqual(self._semantic("INV-BRIDGE-002", fp), [])

    def test_bridge_002_slither_ir_suppresses_restricted_registration_false_positive(self) -> None:
        source = """
        contract Registry {
          mapping(uint256 => address) public machines;
          function registerStateMachine(uint256 chainId, address client) external restricted {
            machines[chainId] = client;
          }
        }
        """
        ir_safe = _FakeFunction(
            [_FakeNode("machines[chainId] = client", writes=("machines",))],
            source=source,
            name="registerStateMachine",
            modifiers=("restricted",),
        )
        with mock.patch.object(
            ltir_mod,
            "_slither_candidate_functions_for_predicate",
            return_value=[ir_safe],
        ):
            self.assertEqual(self._semantic("INV-BRIDGE-002", source), [])

    def test_bridge_002_regex_fallback_still_flags_ungated_registration(self) -> None:
        source = """
        contract Registry {
          mapping(uint256 => address) public clients;
          function registerStateMachine(uint256 chainId, address client) external {
            clients[chainId] = client;
          }
        }
        """
        with mock.patch.object(ltir_mod, "_p1_predicate_bridge_002_slither", return_value=None):
            self.assertEqual(self._semantic("INV-BRIDGE-002", source), ["INV-BRIDGE-002"])

    def test_bridge_003_commitment_consumed_before_external_call(self) -> None:
        tp = """
        contract BridgePayout {
          mapping(bytes32 => bool) public commitments;
          function execute(bytes32 h, address payable to, bytes calldata data) external {
            require(commitments[h], "missing");
            (bool ok,) = to.call{value: 1 ether}(data);
            require(ok);
            commitments[h] = false;
          }
        }
        """
        fp = """
        contract BridgePayout {
          mapping(bytes32 => bool) public commitments;
          mapping(bytes32 => bool) public consumed;
          function execute(bytes32 h, address payable to, bytes calldata data) external {
            require(commitments[h], "missing");
            consumed[h] = true;
            (bool ok,) = to.call{value: 1 ether}(data);
            require(ok);
          }
        }
        """
        self.assertEqual(self._semantic("INV-BRIDGE-003", tp), ["INV-BRIDGE-003"])
        self.assertEqual(self._semantic("INV-BRIDGE-003", fp), [])

    def test_bridge_003_regex_fallback_still_flags_canonical_post_call_write(self) -> None:
        source = """
        contract BridgePayout {
          mapping(bytes32 => bool) public commitments;
          function execute(bytes32 commitment, address payable to, bytes calldata data) external {
            require(commitments[commitment], "missing");
            (bool ok,) = to.call{value: 1 ether}(data);
            require(ok);
            commitments[commitment] = false;
          }
        }
        """
        with mock.patch.object(ltir_mod, "_p1_predicate_bridge_003_slither", return_value=None):
            self.assertEqual(self._semantic("INV-BRIDGE-003", source), ["INV-BRIDGE-003"])

    def test_bridge_003_slither_ir_suppresses_truthy_prewrite_before_call(self) -> None:
        source = """
        contract EvmHost {
          mapping(bytes32 => address) private _requestReceipts;
          function execute(bytes32 commitment, address payable to, bytes calldata data, address relayer) external {
            require(_requestReceipts[commitment] == address(0), "used");
            _requestReceipts[commitment] = relayer;
            (bool ok,) = to.call{value: 1 ether}(data);
            require(ok);
          }
        }
        """
        ir_safe = _FakeFunction(
            [
                _FakeNode("require(_requestReceipts[commitment] == address(0))", reads=("_requestReceipts",)),
                _FakeNode("_requestReceipts[commitment] = relayer", writes=("_requestReceipts",)),
                _FakeNode("(ok,) = to.call{value: 1 ether}(data)", low_level_call=True),
            ]
        )
        with mock.patch.object(
            ltir_mod,
            "_slither_candidate_functions_for_predicate",
            return_value=[ir_safe],
        ):
            self.assertEqual(self._semantic("INV-BRIDGE-003", source), [])

    def test_bridge_003_ir_prewrite_wins_over_regex_false_positive(self) -> None:
        source = """
        contract BridgePayout {
          mapping(bytes32 => address) public commitments;
          function execute(bytes32 commitment, address payable to, bytes calldata data, address relayer) external {
            commitments[commitment] = relayer;
            (bool ok,) = to.call{value: 1 ether}(data);
            require(ok);
          }
        }
        """
        ir_safe = _FakeFunction(
            [
                _FakeNode("commitments[commitment] = relayer", writes=("commitments",)),
                _FakeNode("(ok,) = to.call{value: 1 ether}(data)", low_level_call=True),
            ]
        )
        with mock.patch.object(
            ltir_mod,
            "_slither_candidate_functions_for_predicate",
            return_value=[ir_safe],
        ):
            self.assertEqual(self._semantic("INV-BRIDGE-003", source), [])

    def test_bridge_003_nonreentrant_suppresses_slither_call_before_postwrite(self) -> None:
        source = """
        contract BridgePayout {
          mapping(bytes32 => bool) public commitments;
          function execute(bytes32 commitment, address payable to, bytes calldata data) external nonReentrant {
            require(commitments[commitment], "missing");
            (bool ok,) = to.call{value: 1 ether}(data);
            require(ok);
            commitments[commitment] = false;
          }
        }
        """
        ir_safe = _FakeFunction(
            [
                _FakeNode("require(commitments[commitment])", reads=("commitments",)),
                _FakeNode("(ok,) = to.call{value: 1 ether}(data)", low_level_call=True),
                _FakeNode("commitments[commitment] = false", writes=("commitments",)),
            ],
            source=source,
            name="execute",
            modifiers=("nonReentrant",),
        )
        with mock.patch.object(
            ltir_mod,
            "_slither_candidate_functions_for_predicate",
            return_value=[ir_safe],
        ):
            self.assertEqual(self._semantic("INV-BRIDGE-003", source), [])

    def test_bridge_003_regex_fallback_ignores_nonreentrant_when_slither_missing(self) -> None:
        source = """
        contract BridgePayout {
          mapping(bytes32 => bool) public commitments;
          function execute(bytes32 commitment, address payable to, bytes calldata data) external nonReentrant {
            require(commitments[commitment], "missing");
            (bool ok,) = to.call{value: 1 ether}(data);
            require(ok);
            commitments[commitment] = false;
          }
        }
        """
        with mock.patch.object(ltir_mod, "_p1_predicate_bridge_003_slither", return_value=None):
            self.assertEqual(self._semantic("INV-BRIDGE-003", source), ["INV-BRIDGE-003"])

    def test_bridge_003_nonreentrant_without_commitment_hazard_stays_negative(self) -> None:
        source = """
        contract BridgePayout {
          function ping(address payable to, bytes calldata data) external nonReentrant {
            (bool ok,) = to.call(data);
            require(ok);
          }
        }
        """
        ir_safe = _FakeFunction(
            [_FakeNode("(ok,) = to.call(data)", low_level_call=True)],
            source=source,
            name="ping",
            modifiers=("nonReentrant",),
        )
        with mock.patch.object(
            ltir_mod,
            "_slither_candidate_functions_for_predicate",
            return_value=[ir_safe],
        ):
            self.assertEqual(self._semantic("INV-BRIDGE-003", source), [])

    def test_bridge_004_replay_tuple_tracks_source_chain_and_nonce(self) -> None:
        tp = """
        contract BridgeReceiver {
          function handleMessage(uint256 sourceChain, uint64 nonce, bytes calldata payload) external onlyBridge {
            _deliver(sourceChain, nonce, payload);
          }
        }
        """
        fp = """
        contract BridgeReceiver {
          mapping(uint256 => mapping(uint64 => bool)) public processedNonces;
          function handleMessage(uint256 sourceChain, uint64 nonce, bytes calldata payload) external onlyBridge {
            require(!processedNonces[sourceChain][nonce], "replay");
            processedNonces[sourceChain][nonce] = true;
            _deliver(sourceChain, nonce, payload);
          }
        }
        """
        self.assertEqual(self._semantic("INV-BRIDGE-004", tp), ["INV-BRIDGE-004"])
        self.assertEqual(self._semantic("INV-BRIDGE-004", fp), [])

    def test_bridge_004_slither_ir_suppresses_idiomatic_replay_storage_name(self) -> None:
        source = """
        contract BridgeReceiver {
          mapping(uint256 => mapping(uint64 => address)) public arrivals;
          function handleMessage(uint256 sourceChain, uint64 nonce, bytes calldata payload, address relayer) external onlyBridge {
            require(arrivals[sourceChain][nonce] == address(0), "replay");
            arrivals[sourceChain][nonce] = relayer;
            _deliver(sourceChain, nonce, payload);
          }
        }
        """
        ir_safe = _FakeFunction(
            [
                _FakeNode(
                    "require(arrivals[sourceChain][nonce] == address(0))",
                    reads=("arrivals",),
                ),
                _FakeNode(
                    "arrivals[sourceChain][nonce] = relayer",
                    writes=("arrivals",),
                ),
            ],
            source=source,
            name="handleMessage",
        )
        with mock.patch.object(
            ltir_mod,
            "_slither_candidate_functions_for_predicate",
            return_value=[ir_safe],
        ):
            self.assertEqual(self._semantic("INV-BRIDGE-004", source), [])

    def test_bridge_004_regex_fallback_still_flags_missing_replay_tracking(self) -> None:
        source = """
        contract BridgeReceiver {
          function handleMessage(uint256 sourceChain, uint64 nonce, bytes calldata payload) external onlyBridge {
            _deliver(sourceChain, nonce, payload);
          }
        }
        """
        with mock.patch.object(ltir_mod, "_p1_predicate_bridge_004_slither", return_value=None):
            self.assertEqual(self._semantic("INV-BRIDGE-004", source), ["INV-BRIDGE-004"])

    def test_bridge_004_hash_commitment_replay_missing_should_hit(self) -> None:
        source = """
        contract ResponseDispatcher {
          struct PostRequest { bytes source; }
          struct PostResponse { PostRequest request; }

          function onAccept(PostResponse memory response, bytes calldata payload, address destination) external onlyHost {
            bytes32 commitment = response.request.hash();
            (bool success,) = destination.call(payload);
            require(success, "dispatch failed");
            emit Delivered(commitment);
          }
        }
        """
        self.assertEqual(self._semantic("INV-BRIDGE-004", source), ["INV-BRIDGE-004"])

    def test_hyperbridge_dispatch_incoming_hash_receipt_prewrite_stays_negative_for_bridge_004(self) -> None:
        source = """
        contract EvmHost {
          mapping(bytes32 => address) private _requestReceipts;
          struct PostRequest { bytes source; }

          function dispatchIncoming(
            PostRequest memory request,
            bytes calldata payload,
            address destination,
            address relayer
          ) external onlyHost {
            bytes32 commitment = request.hash();
            require(_requestReceipts[commitment] == address(0), "duplicate");
            _requestReceipts[commitment] = relayer;
            (bool success,) = destination.call(payload);
            if (!success) {
              delete _requestReceipts[commitment];
              return;
            }
          }
        }
        """
        self.assertEqual(self._semantic("INV-BRIDGE-004", source), [])

    def test_bridge_004_slither_ir_suppresses_request_hash_receipt_tracking(self) -> None:
        source = """
        contract EvmHost {
          mapping(bytes32 => address) private _requestReceipts;
          struct PostRequest { bytes source; }

          function dispatchIncoming(
            PostRequest memory request,
            bytes calldata payload,
            address destination,
            address relayer
          ) external onlyHost {
            bytes32 commitment = request.hash();
            require(_requestReceipts[commitment] == address(0), "duplicate");
            _requestReceipts[commitment] = relayer;
            (bool success,) = destination.call(payload);
            if (!success) {
              delete _requestReceipts[commitment];
              return;
            }
          }
        }
        """
        ir_safe = _FakeFunction(
            [
                _FakeNode("bytes32 commitment = request.hash()"),
                _FakeNode(
                    "require(_requestReceipts[commitment] == address(0), \"duplicate\")",
                    reads=("_requestReceipts",),
                ),
                _FakeNode(
                    "_requestReceipts[commitment] = relayer",
                    writes=("_requestReceipts",),
                ),
                _FakeNode("(bool success,) = destination.call(payload)", low_level_call=True),
                _FakeNode("delete _requestReceipts[commitment]", writes=("_requestReceipts",)),
            ],
            source=source,
            name="dispatchIncoming",
            modifiers=("onlyHost",),
        )
        with mock.patch.object(
            ltir_mod,
            "_slither_candidate_functions_for_predicate",
            return_value=[ir_safe],
        ):
            self.assertEqual(self._semantic("INV-BRIDGE-004", source), [])

    def test_bridge_005_finality_proof_requires_freshness_window(self) -> None:
        tp = """
        contract LightClient {
          struct Proof { uint256 height; bytes proof; }
          function acceptState(bytes32 root, Proof calldata finalityProof) external {
            require(_verify(finalityProof.proof, root));
            roots[finalityProof.height] = root;
          }
        }
        """
        fp = """
        contract LightClient {
          uint256 constant FRESHNESS_WINDOW = 1024;
          struct Proof { uint256 height; bytes proof; }
          function acceptState(bytes32 root, Proof calldata finalityProof) external {
            require(block.number - finalityProof.height < FRESHNESS_WINDOW, "stale");
            require(_verify(finalityProof.proof, root));
            roots[finalityProof.height] = root;
          }
        }
        """
        self.assertEqual(self._semantic("INV-BRIDGE-005", tp), ["INV-BRIDGE-005"])
        self.assertEqual(self._semantic("INV-BRIDGE-005", fp), [])

    def test_hyperbridge_solver_account_low_level_call_stays_topical_for_bridge_003(self) -> None:
        source = """
        contract SolverAccount {
          address private immutable INTENT_GATEWAY_V2;
          function validate(bytes32 commitment, bytes calldata selectCalldata) external returns (bool) {
            (bool success, bytes memory returnData) = INTENT_GATEWAY_V2.call(selectCalldata);
            if (!success || returnData.length < 32) return false;
            return commitment != bytes32(0);
          }
        }
        """
        self.assertEqual(self._semantic("INV-BRIDGE-003", source), [])

    def test_hyperbridge_intents_withdraw_updates_state_before_external_call(self) -> None:
        source = """
        contract IntentsBase {
          mapping(bytes32 => mapping(address => uint256)) private _orders;
          function withdraw(bytes32 commitment, address beneficiary, address token, uint256 amount) external {
            uint256 escrowed = _orders[commitment][token];
            _orders[commitment][token] = escrowed - amount;
            (bool sent,) = beneficiary.call{value: amount}("");
            require(sent, "send failed");
          }
        }
        """
        self.assertEqual(self._semantic("INV-BRIDGE-003", source), [])

    def test_hyperbridge_dispatch_incoming_prewrite_suppresses_bridge_003(self) -> None:
        source = """
        contract EvmHost {
          mapping(bytes32 => address) private _requestReceipts;
          function dispatchIncoming(bytes32 commitment, address destination, bytes calldata payload, address relayer) external {
            _requestReceipts[commitment] = relayer;
            (bool success,) = destination.call(payload);
            if (!success) {
              delete _requestReceipts[commitment];
              return;
            }
          }
        }
        """
        self.assertEqual(self._semantic("INV-BRIDGE-003", source), [])

    def test_hyperbridge_dispatch_incoming_retry_delete_stays_negative_for_bridge_003(self) -> None:
        source = """
        contract EvmHost {
          mapping(bytes32 => address) private _requestReceipts;
          function dispatchIncoming(bytes32 commitment, address destination, bytes calldata payload, address relayer) external {
            address cachedRelayer = _requestReceipts[commitment];
            if (cachedRelayer == address(0)) {
              _requestReceipts[commitment] = relayer;
            }
            (bool success,) = destination.call(payload);
            if (!success) {
              delete _requestReceipts[commitment];
              return;
            }
            delete _requestReceipts[commitment];
          }
        }
        """
        self.assertEqual(self._semantic("INV-BRIDGE-003", source), [])

    def test_hyperbridge_layerzero_guarded_delivery_stays_negative_for_bridge_001_and_004(self) -> None:
        source = """
        contract HyperbridgeLzEndpoint {
          address public host;
          mapping(bytes32 => uint32) private _stateMachineToEid;
          mapping(address => mapping(uint32 => mapping(address => uint64))) private _inboundNonce;

          function onAccept(IncomingPostRequest calldata incoming) external override onlyHost whenNotPaused {
            PostRequest calldata request = incoming.request;
            bytes32 sourceHash = keccak256(request.source);
            if (keccak256(request.from) != keccak256(abi.encodePacked(address(this)))) revert UnknownSource();
            uint32 expectedEid = _stateMachineToEid[sourceHash];
            if (expectedEid == 0 || expectedEid != incoming.srcEid) revert UnknownSource();
            uint64 expectedNonce = _inboundNonce[receiverAddr][incoming.srcEid][sender] + 1;
            if (incoming.nonce != expectedNonce) revert InvalidNonce(expectedNonce, incoming.nonce);
            _inboundNonce[receiverAddr][incoming.srcEid][sender] = incoming.nonce;
            ILayerZeroReceiver(receiverAddr).lzReceive(origin, guid, message, address(0), "");
          }
        }
        """
        self.assertEqual(self._semantic("INV-BRIDGE-001", source), [])
        self.assertEqual(self._semantic("INV-BRIDGE-004", source), [])

    def test_generic_ecdsa_consensus_proof_docs_stay_negative_for_bridge_004(self) -> None:
        source = """
        # Consensus proof note
        The verifier uses ECDSA.recover to authenticate committee signatures.
        The proof references source chain IDs, nonces, and replay windows as descriptive language only.
        There is no inbound bridge handler and no processedNonces[sourceChain][nonce] state.
        """
        self.assertEqual(
            self._semantic("INV-BRIDGE-004", source),
            [],
        )

    def test_bridge_006_verify_bridge_proof_camelcase_missing_destination_binding_should_hit(self) -> None:
        source = """
        contract BridgeVerifier {
          function verifyBridgeProof(
            uint32 sourceDomain,
            uint32 destinationDomain,
            bytes32 root,
            bytes32 leaf,
            uint256 nonce
          ) external pure returns (bytes32) {
            destinationDomain;
            return keccak256(abi.encode(sourceDomain, root, leaf, nonce, "bridgeProof"));
          }
        }
        """
        with mock.patch.object(ltir_mod, "_p1_predicate_bridge_006_slither", return_value=None):
            self.assertEqual(self._semantic("INV-BRIDGE-006", source), ["INV-BRIDGE-006"])

    def test_bridge_006_verify_bridge_proof_with_destination_binding_stays_negative(self) -> None:
        source = """
        contract BridgeVerifier {
          function verifyBridgeProof(
            uint32 sourceDomain,
            uint32 destinationDomain,
            bytes32 root,
            bytes32 leaf,
            uint256 nonce
          ) external pure returns (bytes32) {
            return keccak256(abi.encode(sourceDomain, destinationDomain, root, leaf, nonce, "bridgeProof"));
          }
        }
        """
        with mock.patch.object(ltir_mod, "_p1_predicate_bridge_006_slither", return_value=None):
            self.assertEqual(self._semantic("INV-BRIDGE-006", source), [])

    def test_bridge_006_verify_bridge_proof_without_source_binding_stays_negative(self) -> None:
        source = """
        contract BridgeVerifier {
          function verifyBridgeProof(
            uint32 sourceDomain,
            uint32 destinationDomain,
            bytes32 root,
            bytes32 leaf,
            uint256 nonce
          ) external pure returns (bytes32) {
            sourceDomain;
            destinationDomain;
            return keccak256(abi.encode(root, leaf, nonce, "bridgeProof"));
          }
        }
        """
        with mock.patch.object(ltir_mod, "_p1_predicate_bridge_006_slither", return_value=None):
            self.assertEqual(self._semantic("INV-BRIDGE-006", source), [])

    def test_mmr_membership_only_verifier_with_receipt_guard_stays_negative_for_bridge_006(self) -> None:
        source = """
        contract BridgeVerifier {
          uint32 constant LOCAL_DOMAIN = 200;
          mapping(bytes32 => bool) public processed;

          struct ProofLeaf {
            uint256 index;
            bytes32 messageHash;
            uint32 sourceDomain;
            uint32 destinationDomain;
          }

          function verifyAndDispatch(ProofLeaf calldata leaf, bytes32[] calldata proof, bytes32 root, uint256 leafCount) external {
            if (leaf.destinationDomain != LOCAL_DOMAIN) revert WrongDestination();
            MerkleMountainRange.Leaf[] memory leaves = new MerkleMountainRange.Leaf[](1);
            leaves[0] = MerkleMountainRange.Leaf(leaf.index, leaf.messageHash);
            require(MerkleMountainRange.VerifyProof(root, proof, leaves, leafCount), "bad proof");
            require(!processed[leaf.messageHash], "duplicate");
            processed[leaf.messageHash] = true;
            _dispatch(leaf.sourceDomain, leaf.destinationDomain, leaf.messageHash);
          }
        }
        """
        self.assertEqual(self._semantic("INV-BRIDGE-006", source), [])

    def test_mmr_membership_only_docs_stay_negative_for_bridge_006(self) -> None:
        source = """
        # Merkle Mountain Range note
        The verifier provides membership proofs only and is not positionally binding.
        If the application requires positional binding, commit the leaf index into the leaf hash.
        This note mentions sourceDomain and destinationDomain as bridge context, but it is documentation only.
        """
        self.assertEqual(self._semantic("INV-BRIDGE-006", source), [])

    def test_cap020_live_target_p3_filter_drops_utility_proof_noise(self) -> None:
        pattern_id = ltir_mod.CAP020_BRIDGE_PROOF_PATTERN_ID
        utility_source = """
        library EthereumTrie {
          function verify(bytes32 root, bytes32 branch) internal pure returns (bool) {
            return root != bytes32(0) && branch != bytes32(0);
          }
        }
        """
        filtered = ltir_mod._filter_live_target_p3_matches(
            [pattern_id, "solidity.division-by-zero", "no-P3-match:authorization:go"],
            file_hint="src/solidity-merkle-trees/src/EthereumTrie.sol:205",
            snippet="return root != bytes32(0) && branch != bytes32(0);",
            source_context=utility_source,
            source_contract_context=utility_source,
        )
        self.assertNotIn(pattern_id, filtered)
        self.assertIn("solidity.division-by-zero", filtered)
        self.assertIn("no-P3-match:authorization:go", filtered)

    def test_cap020_live_target_p3_filter_keeps_bridge_domain_proof_verifier(self) -> None:
        pattern_id = ltir_mod.CAP020_BRIDGE_PROOF_PATTERN_ID
        bridge_source = """
        contract BridgeVerifier {
          uint32 public sourceDomain;
          uint32 public destinationDomain;

          function verifyBridgeProof(bytes32 root, bytes32 branch) external view returns (bool) {
            require(root != bytes32(0), "zero root");
            require(branch != bytes32(0), "default branch");
            return sourceDomain != destinationDomain;
          }
        }
        """
        filtered = ltir_mod._filter_live_target_p3_matches(
            [pattern_id],
            file_hint="src/hyperbridge/evm/src/apps/BridgeVerifier.sol:10",
            snippet='require(root != bytes32(0), "zero root");',
            source_context=bridge_source,
            source_contract_context=bridge_source,
        )
        self.assertEqual(filtered, [pattern_id])

    def test_unchecked_low_level_call_with_checked_result_is_suppressed(self) -> None:
        solver_source = """
        contract SolverAccount {
          function validate(bytes calldata selectCalldata) external returns (uint256) {
            (bool success, bytes memory returnData) = INTENT_GATEWAY_V2.call(selectCalldata);
            if (!success || returnData.length < 32) return SIG_VALIDATION_FAILED;
            return SIG_VALIDATION_SUCCESS;
          }
        }
        """
        solver = ltir_mod._detector_false_positive_suppression(
            "unchecked-low-level-call",
            file_line="src/hyperbridge/evm/src/apps/intentsv2/SolverAccount.sol:100",
            snippet="(bool success, bytes memory returnData) = INTENT_GATEWAY_V2.call(selectCalldata);",
            source_context=solver_source,
            source_contract_context=solver_source,
        )
        self.assertTrue(solver["suppressed"])
        self.assertTrue(any("CAP-022" in reason for reason in solver["reasons"]))

        evm_host_source = """
        contract EvmHost {
          mapping(bytes32 => address) private _requestReceipts;
          function dispatchIncoming(PostRequest memory request, address relayer) external {
            bytes32 commitment = request.hash();
            _requestReceipts[commitment] = relayer;
            (bool success,) = address(destination)
              .call(abi.encodeWithSelector(IApp.onAccept.selector, IncomingPostRequest(request, relayer)));
            if (!success) {
              delete _requestReceipts[commitment];
              return;
            }
          }
        }
        """
        evm_host = ltir_mod._detector_false_positive_suppression(
            "unchecked-low-level-call",
            file_line="src/hyperbridge/evm/src/core/EvmHost.sol:810",
            snippet=".call(abi.encodeWithSelector(IApp.onAccept.selector, IncomingPostRequest(request, relayer)));",
            source_context=evm_host_source,
            source_contract_context=evm_host_source,
        )
        self.assertTrue(evm_host["suppressed"])
        self.assertTrue(any("CAP-022" in reason for reason in evm_host["reasons"]))

        unsafe_source = """
        contract Unsafe {
          function send(address target, bytes calldata data) external {
            (bool ok,) = target.call(data);
            emitted = true;
          }
        }
        """
        unsafe = ltir_mod._detector_false_positive_suppression(
            "unchecked-low-level-call",
            file_line="src/Unsafe.sol:4",
            snippet="(bool ok,) = target.call(data);",
            source_context=unsafe_source,
            source_contract_context=unsafe_source,
        )
        self.assertFalse(unsafe["suppressed"])

    def test_signature_without_nonce_proof_context_is_suppressed_but_bridge_nonce_shape_is_not(self) -> None:
        solver_source = """
        contract SolverAccount {
          function _rawSignatureValidation(bytes32 hash, bytes calldata signature) internal pure returns (bool) {
            return ECDSA.recover(hash, signature) == address(this);
          }
          function validate(bytes32 hash, bytes calldata signature) external returns (bool) {
            return _rawSignatureValidation(hash, signature);
          }
        }
        """
        solver = ltir_mod._detector_false_positive_suppression(
            "signature-without-nonce",
            file_line="src/hyperbridge/evm/src/apps/intentsv2/SolverAccount.sol:137",
            snippet="Delegates to {_rawSignatureValidation} which performs ECDSA recovery",
            source_context=solver_source,
            source_contract_context=solver_source,
        )
        self.assertTrue(solver["suppressed"])
        self.assertTrue(any("CAP-021" in reason for reason in solver["reasons"]))

        beefy_source = """
        contract EcdsaBeefy {
          function verify(bytes32 digest, bytes calldata signature) external view returns (bool) {
            address signer = ecrecover(digest, 27, bytes32(0), bytes32(0));
            return signer != address(0) && authority[signer];
          }
        }
        """
        beefy = ltir_mod._detector_false_positive_suppression(
            "signature-without-nonce",
            file_line="src/hyperbridge/evm/src/consensus/EcdsaBeefy.sol:54",
            snippet="Recover signer addresses via ecrecover and verify their membership in the authority",
            source_context=beefy_source,
            source_contract_context=beefy_source,
        )
        self.assertTrue(beefy["suppressed"])
        self.assertTrue(any("CAP-021" in reason for reason in beefy["reasons"]))

        beefy_comment_context = """
        /**
         * @notice Verifies BEEFY consensus proofs by checking a 2/3+1 supermajority of secp256k1
         * signatures on-chain, along with merkle multi-proofs of authority set membership.
         *
         * @dev The verification flow is:
         *  3. Recover signer addresses via ecrecover and verify their membership in the authority
         *     set via a merkle multi-proof against the authority set root.
         */
        contract EcdsaBeefy {}
        """
        beefy_comment = ltir_mod._detector_false_positive_suppression(
            "signature-without-nonce",
            file_line="src/hyperbridge/evm/src/consensus/EcdsaBeefy.sol:54",
            snippet="Recover signer addresses via ecrecover and verify their membership in the authority",
            source_context=beefy_comment_context,
            source_contract_context="",
        )
        self.assertTrue(beefy_comment["suppressed"])
        self.assertTrue(any("CAP-021" in reason for reason in beefy_comment["reasons"]))

        bridge_nonce_source = """
        contract BridgeReceiver {
          mapping(uint256 => mapping(uint64 => bool)) public processedNonces;
          function handleMessage(uint256 sourceChain, uint64 nonce, bytes calldata payload) external {
            require(!processedNonces[sourceChain][nonce], "replay");
            processedNonces[sourceChain][nonce] = true;
            bytes32 digest = keccak256(payload);
            address signer = ecrecover(digest, 27, bytes32(0), bytes32(0));
            require(signer != address(0));
          }
        }
        """
        bridge = ltir_mod._detector_false_positive_suppression(
            "signature-without-nonce",
            file_line="src/BridgeReceiver.sol:1",
            snippet="handleMessage(uint256 sourceChain, uint64 nonce, bytes calldata payload)",
            source_context=bridge_nonce_source,
            source_contract_context=bridge_nonce_source,
        )
        self.assertFalse(bridge["suppressed"])


if __name__ == "__main__":
    unittest.main()
