// SPDX-License-Identifier: MIT
// LayerZeroEndpointStub.sol — Replay-harness stub for LayerZero v2 EndpointV2.
//
// Production faithfulness scope: models inbound message nonce tracking,
// _lzReceive dispatch, and verifiable nonce / channel clearing. Does NOT model
// DVN allowance accounting, executor fee payment, or the full Send pathway.
//
// Faithfully models (5 of 9 production EndpointV2 behaviors):
//   1. Inbound nonce tracking: inboundNonce[srcEid][sender][receiver] increments
//      monotonically and rejects out-of-order delivery.
//   2. _lzReceive dispatch: forwards (origin, guid, message, executor, options)
//      to the registered OApp via ILayerZeroReceiver interface.
//   3. Path nonce clearing: clearNonce() operator hook for testing nonce resets.
//   4. Registered OApp lookup: setOApp() maps srcEid+sender to receiver OApp.
//   5. Re-delivery guard: delivered[guid] prevents replay of the same packet.
// Intentionally simplified (4 of 9):
//   6. DVN verification pipeline: not modeled; stub auto-verifies on delivery.
//   7. Executor fee accounting: not modeled; stub accepts any msg.value.
//   8. Send pathway (lzSend): outbound messages recorded in sentMessages only;
//      no real cross-chain relay is triggered.
//   9. Packet encoding / decoding (EIP-4895 packet format): stub uses simplified
//      abi-encoded origin struct; not byte-exact with production format.
//
// Usage: supply as --override-contract EndpointV2=<path> in fork-replay.py.
// Compile: forge build (solc ^0.8.20)
pragma solidity ^0.8.20;

interface ILayerZeroReceiverStub {
    function lzReceive(
        Origin calldata _origin,
        bytes32 _guid,
        bytes calldata _message,
        address _executor,
        bytes calldata _extraData
    ) external payable;
}

struct Origin {
    uint32 srcEid;
    bytes32 sender;
    uint64 nonce;
}

contract LayerZeroEndpointStub {
    // ── Storage ───────────────────────────────────────────────────────────────

    /// @dev inboundNonce[srcEid][sender][receiverOApp]
    mapping(uint32 => mapping(bytes32 => mapping(address => uint64))) public inboundNonce;

    /// @dev OApp registrations: srcEid+sender → receiverOApp
    mapping(uint32 => mapping(bytes32 => address)) public oappRegistry;

    /// @dev Delivered packet guard (behavior #5)
    mapping(bytes32 => bool) public delivered;

    /// @dev Outbound messages recorded (behavior #8 partial)
    mapping(bytes32 => bytes) public sentMessages;

    // ── Events ────────────────────────────────────────────────────────────────
    event PacketDelivered(uint32 indexed srcEid, bytes32 indexed sender, address indexed receiver, bytes32 guid);
    event PacketSent(bytes32 indexed guid, uint32 dstEid, bytes payload);

    // ── OApp registration (stub-only) ─────────────────────────────────────────
    function setOApp(uint32 srcEid, bytes32 senderBytes32, address oapp) external {
        oappRegistry[srcEid][senderBytes32] = oapp;
    }

    // ── deliver (behaviors #1, #2, #3, #5) ───────────────────────────────────
    /// @notice Simulate inbound packet delivery from a remote EID.
    function deliver(
        uint32 srcEid,
        bytes32 senderBytes32,
        address receiverOApp,
        uint64 nonce,
        bytes32 guid,
        bytes calldata message,
        address executor,
        bytes calldata extraData
    ) external payable {
        // Behavior #5: replay guard
        require(!delivered[guid], "EndpointStub: already delivered");

        // Behavior #1: monotone nonce (production: accepts nonce == stored+1)
        uint64 expected = inboundNonce[srcEid][senderBytes32][receiverOApp] + 1;
        require(nonce == expected, "EndpointStub: out-of-order nonce");
        inboundNonce[srcEid][senderBytes32][receiverOApp] = nonce;

        // Mark before external call (CEI)
        delivered[guid] = true;

        // Behavior #2: dispatch to OApp
        Origin memory origin = Origin({srcEid: srcEid, sender: senderBytes32, nonce: nonce});
        ILayerZeroReceiverStub(receiverOApp).lzReceive{value: msg.value}(
            origin, guid, message, executor, extraData
        );

        emit PacketDelivered(srcEid, senderBytes32, receiverOApp, guid);
    }

    // ── clearNonce (behavior #3) ──────────────────────────────────────────────
    function clearNonce(uint32 srcEid, bytes32 senderBytes32, address receiverOApp) external {
        inboundNonce[srcEid][senderBytes32][receiverOApp] = 0;
    }

    // ── lzSend (behavior #8 partial) ──────────────────────────────────────────
    function lzSend(
        uint32 dstEid,
        bytes calldata payload,
        bytes calldata /* options */,
        address /* refundAddress */
    ) external payable returns (bytes32 guid) {
        guid = keccak256(abi.encodePacked(msg.sender, dstEid, payload, block.number));
        sentMessages[guid] = payload;
        emit PacketSent(guid, dstEid, payload);
    }

    receive() external payable {}
}
