// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULNERABLE: recovers a signer and transfers, but never marks the
// signature/digest/nonce consumed - the signature is replayable forever.
contract RecoverNoNonceVulnerable {
    mapping(address => uint256) public balance;

    function withdrawWithSig(
        address owner,
        address to,
        uint256 amount,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 digest = keccak256(abi.encodePacked(owner, to, amount));
        address signer = ecrecover(digest, v, r, s);
        require(signer == owner, "bad sig");
        balance[owner] -= amount;
        balance[to] += amount;
    }
}
