// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: per-owner nonce is incremented in the body, so each signature is
// single-use.
contract RecoverNoNonceClean {
    mapping(address => uint256) public balance;
    mapping(address => uint256) public nonces;

    function withdrawWithSig(
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
