// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire. Same shape as the vuln
/// fixture, but the transferId is bound to a source-side signature via
/// ecrecover before any funds move.
contract BridgeTransferIdClean {
    address public bridge;
    address public messenger;
    address public attester;
    mapping(bytes32 => bool) public nonces;
    mapping(address => uint256) public escrow;

    constructor(address _bridge, address _messenger, address _attester) {
        bridge = _bridge;
        messenger = _messenger;
        attester = _attester;
    }

    function finalizeBridgeERC20(
        address recipient,
        uint256 amount,
        bytes32 transferId,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(!nonces[transferId], "already finalized");
        nonces[transferId] = true;

        // Verify the transferId is authentic: attester signed
        // (recipient, amount, transferId) on the source side.
        bytes32 digest = keccak256(abi.encodePacked(recipient, amount, transferId));
        address signer = ecrecover(digest, v, r, s);
        require(signer == attester, "bad attester");

        escrow[recipient] += amount;
    }
}
