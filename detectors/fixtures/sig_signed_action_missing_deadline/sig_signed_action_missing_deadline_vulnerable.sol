// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULNERABLE: signed action has a nonce but NO deadline / expiry. A leaked
// or stale signature is a perpetual bearer credential.
contract MissingDeadlineVulnerable {
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public balance;

    function executeWithSig(
        address owner,
        address to,
        uint256 amount,
        uint256 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(nonce == nonces[owner], "bad nonce");
        bytes32 digest = keccak256(abi.encodePacked(owner, to, amount, nonce));
        address signer = ecrecover(digest, v, r, s);
        require(signer == owner, "bad sig");
        nonces[owner] += 1;
        balance[owner] -= amount;
        balance[to] += amount;
    }
}
