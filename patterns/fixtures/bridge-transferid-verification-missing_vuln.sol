// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// bridge-transferid-verification-missing detector. DO NOT DEPLOY.
///
/// Destination-side settlement function receives a user-supplied
/// `transferId` and releases escrowed tokens based on it, but never
/// verifies that `transferId` was signed or committed on the source chain.
/// Attacker supplies any transferId and drains escrow.
contract BridgeTransferIdVuln {
    address public bridge;
    address public messenger;
    mapping(bytes32 => bool) public nonces;
    mapping(address => uint256) public escrow;

    constructor(address _bridge, address _messenger) {
        bridge = _bridge;
        messenger = _messenger;
    }

    /// @dev Uses `transferId` as a key for bookkeeping but never proves it
    ///      was produced by the source-side bridge. No ecrecover, no
    ///      SignatureChecker, no merkleProof, no verify() call.
    function finalizeBridgeERC20(
        address recipient,
        uint256 amount,
        bytes32 transferId
    ) external {
        require(!nonces[transferId], "already finalized");
        nonces[transferId] = true;

        // Value-bearing side effect, no source-side attestation at all.
        escrow[recipient] += amount;
    }
}
