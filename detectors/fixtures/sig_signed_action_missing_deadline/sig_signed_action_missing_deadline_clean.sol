// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: signed action carries a `deadline` field, checked against
// block.timestamp before the recovered signer is trusted.
contract MissingDeadlineClean {
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public balance;

    function executeWithSig(
        address owner,
        address to,
        uint256 amount,
        uint256 nonce,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(block.timestamp <= deadline, "expired");
        require(nonce == nonces[owner], "bad nonce");
        bytes32 digest = keccak256(
            abi.encodePacked(owner, to, amount, nonce, deadline)
        );
        address signer = ecrecover(digest, v, r, s);
        require(signer == owner, "bad sig");
        nonces[owner] += 1;
        balance[owner] -= amount;
        balance[to] += amount;
    }
}
