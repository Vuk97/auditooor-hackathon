// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// positive.sol - bridge-proof-domain-bypass-umbrella
// Demonstrates shape: destination settlement marks id used and releases funds
// WITHOUT verifying the transferId against any source-chain commitment.
// The replay key (processed mapping) is NOT scoped to (src, dst) chain pair.

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract VulnBridgeSettlement {
    mapping(bytes32 => bool) public processed;
    IERC20 public token;
    address public owner;

    // VULN: accepts transferId, marks processed, releases tokens
    // WITHOUT verifying against a source-chain Merkle proof or signature.
    // transferId is fully attacker-controlled.
    function finalizeBridgeERC20(
        address recipient,
        uint256 amount,
        bytes32 transferId
    ) external {
        require(!processed[transferId], "already processed");
        processed[transferId] = true;
        // No source-chain commitment check here - transferId is untrusted
        token.transfer(recipient, amount);
    }

    // VULN shape 2: Fiat-Shamir transcript omits validator-set domain.
    // proofHash is keccak256(message) but does NOT include validatorSetHash.
    function verifyAndRelease(
        bytes32 messageId,
        bytes32 proofHash,
        uint256 amount,
        address recipient
    ) external {
        require(!processed[messageId], "already processed");
        // The proofHash is keccak256(abi.encode(messageId, amount, recipient))
        // - does NOT include validatorSetDomain or chainId in preimage.
        require(proofHash == keccak256(abi.encode(messageId, amount, recipient)), "bad proof");
        processed[messageId] = true;
        token.transfer(recipient, amount);
    }
}
