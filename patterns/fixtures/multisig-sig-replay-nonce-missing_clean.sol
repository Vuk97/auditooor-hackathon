// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire. Same execTransaction
/// surface as the vuln fixture, but every execution binds the digest to a
/// monotonic per-contract nonce that is advanced BEFORE the inner call.

contract MultisigReplayClean {
    address[] public owners;
    uint256 public threshold;
    uint256 public nonce;
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
        // Digest binds the current nonce — once advanced, the same
        // signature set is useless.
        bytes32 digest = keccak256(abi.encode(to, value, keccak256(data), nonce));

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

        // Advance nonce BEFORE inner call — replay impossible even on
        // reentrancy.
        nonce++;

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
