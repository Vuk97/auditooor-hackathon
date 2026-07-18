// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// clean.sol - bridge-proof-domain-bypass-umbrella
// Clean form: domain-scoped replay key + Merkle proof verification.
// Both source AND destination domain are bound in the proof leaf preimage.

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

library MerkleProof {
    function verify(bytes32[] memory proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];
            if (computedHash <= proofElement) {
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            } else {
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            }
        }
        return computedHash == root;
    }
}

contract CleanBridgeSettlement {
    mapping(bytes32 => bool) public processed;
    bytes32 public approvedRoot;
    IERC20 public token;
    uint32 public immutable LOCAL_DOMAIN;
    uint32 public immutable REMOTE_DOMAIN;

    constructor(uint32 localDomain, uint32 remoteDomain) {
        LOCAL_DOMAIN = localDomain;
        REMOTE_DOMAIN = remoteDomain;
    }

    // CLEAN: leaf binds both source and destination domain + address(this).
    // Replay key includes (srcDomain, dstDomain) to scope across bridge lanes.
    function finalizeBridgeERC20(
        address recipient,
        uint256 amount,
        bytes32 transferId,
        bytes32[] calldata merkleProof
    ) external {
        // Destination domain check - guards against cross-domain replay.
        require(block.chainid == LOCAL_DOMAIN, "WrongDestination");

        // Domain-scoped replay key prevents cross-lane replay.
        bytes32 replayKey = keccak256(abi.encode(REMOTE_DOMAIN, LOCAL_DOMAIN, transferId));
        require(!processed[replayKey], "already processed");

        // Proof leaf binds sourceDomain + destinationDomain + both parties.
        bytes32 leaf = keccak256(abi.encode(
            REMOTE_DOMAIN,      // source domain bound in leaf
            LOCAL_DOMAIN,       // destination domain bound in leaf
            address(this),      // bridge contract address
            recipient,
            amount,
            transferId
        ));

        require(MerkleProof.verify(merkleProof, approvedRoot, leaf), "bad proof");

        processed[replayKey] = true;
        token.transfer(recipient, amount);
    }
}
