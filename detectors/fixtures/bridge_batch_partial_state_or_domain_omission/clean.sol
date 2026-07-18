// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library MerkleProof {
    function processProof(bytes32[] calldata, bytes32 leaf) internal pure returns (bytes32) {
        return leaf;
    }
}

contract BridgeBatchPartialStateClean {
    struct Command {
        uint8 kind;
        uint256 gas;
        bytes payload;
    }

    struct InboundMessage {
        uint64 nonce;
        uint32 sourceDomain;
        uint32 destinationDomain;
        bytes32 topic;
        Command[] commands;
    }

    mapping(uint64 => bool) public inboundNonce;
    mapping(bytes32 => bool) public registered;
    mapping(address => uint256) public minted;
    uint32 public immutable localDomain;

    error WrongDomain();
    error CommandFailed();

    event InboundMessageDispatched(uint64 indexed nonce, bytes32 topic, bool success);

    constructor(uint32 domain) {
        localDomain = domain;
    }

    function submitInbound(
        InboundMessage calldata message,
        bytes32[] calldata leafProof,
        bytes32 expectedCommitment
    ) external {
        if (message.destinationDomain != localDomain) {
            revert WrongDomain();
        }
        require(!inboundNonce[message.nonce], "already dispatched");

        bytes32 leafHash = keccak256(
            abi.encode(message.sourceDomain, message.destinationDomain, address(this), message)
        );
        bytes32 commitment = MerkleProof.processProof(leafProof, leafHash);
        require(commitment == expectedCommitment, "bad proof");

        bool success = dispatchBatch(message);
        if (!success) {
            revert CommandFailed();
        }

        inboundNonce[message.nonce] = true;
        emit InboundMessageDispatched(message.nonce, message.topic, success);
    }

    function dispatchBatch(InboundMessage calldata message) internal returns (bool) {
        for (uint256 i = 0; i < message.commands.length; i++) {
            if (message.commands[i].kind == 1) {
                try this.handleRegister(message.commands[i].payload) {} catch {
                    return false;
                }
            } else if (message.commands[i].kind == 2) {
                try this.handleMint(message.commands[i].payload) {} catch {
                    return false;
                }
            } else {
                return false;
            }
        }
        return true;
    }

    function submitInboundWithRetryClear(
        InboundMessage calldata message,
        bytes32[] calldata leafProof,
        bytes32 expectedCommitment
    ) external {
        require(!inboundNonce[message.nonce], "already dispatched");
        bytes32 leafHash = keccak256(
            abi.encode(message.sourceDomain, message.destinationDomain, address(this), message)
        );
        require(MerkleProof.processProof(leafProof, leafHash) == expectedCommitment, "bad proof");

        inboundNonce[message.nonce] = true;
        bool success = dispatchBatch(message);
        if (!success) {
            inboundNonce[message.nonce] = false;
            revert CommandFailed();
        }
    }

    function handleRegister(bytes calldata payload) external {
        require(msg.sender == address(this), "only self");
        registered[keccak256(payload)] = true;
    }

    function handleMint(bytes calldata payload) external {
        require(msg.sender == address(this), "only self");
        (address recipient, uint256 amount) = abi.decode(payload, (address, uint256));
        require(registered[keccak256(payload)], "not registered");
        minted[recipient] += amount;
    }
}
