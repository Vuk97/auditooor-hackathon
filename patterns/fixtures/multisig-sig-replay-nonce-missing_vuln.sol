// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// multisig-sig-replay-nonce-missing detector. DO NOT DEPLOY.
///
/// `execTransaction` verifies a batch of owner signatures but computes the
/// digest from (to, value, data) only. No nonce is consumed or advanced,
/// so the same signature set remains valid for any (to, value, data)
/// re-submission — and in fact is valid for the SAME tuple infinitely.

contract MultisigReplayVuln {
    address[] public owners;
    uint256 public threshold;
    mapping(address => bool) public isOwner;

    constructor(address[] memory _owners, uint256 _threshold) {
        owners = _owners;
        threshold = _threshold;
        for (uint256 i = 0; i < _owners.length; i++) {
            isOwner[_owners[i]] = true;
        }
    }

    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        bytes[] calldata signatures
    ) external returns (bool success) {
        // Digest is bound to (to, value, data) only — NO nonce.
        bytes32 digest = keccak256(abi.encode(to, value, keccak256(data)));

        uint256 validSigs = 0;
        address lastSigner = address(0);
        for (uint256 i = 0; i < signatures.length; i++) {
            (uint8 v, bytes32 r, bytes32 s) = _split(signatures[i]);
            address signer = ecrecover(digest, v, r, s);
            require(isOwner[signer], "not owner");
            require(signer > lastSigner, "unordered");
            lastSigner = signer;
            validSigs++;
        }
        require(validSigs >= threshold, "threshold");

        // Dispatch inner call with no nonce advance.
        (success, ) = to.call{value: value}(data);
    }

    function _split(bytes calldata sig) private pure
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        require(sig.length == 65, "bad sig");
        r = bytes32(sig[0:32]);
        s = bytes32(sig[32:64]);
        v = uint8(sig[64]);
    }

    receive() external payable {}
}
