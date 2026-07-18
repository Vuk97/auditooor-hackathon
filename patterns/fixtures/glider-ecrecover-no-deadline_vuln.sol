// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SignedActionVuln {
    mapping(bytes32 => bool) public used;

    /// VULN: ecrecover call has no time-bound -- signature valid indefinitely.
    function claim(address to, uint256 amount, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 h = keccak256(abi.encode(to, amount, nonce));
        address signer = ecrecover(h, v, r, s);
        require(signer == to, "bad sig");
        require(!used[h], "used");
        used[h] = true;
    }
}
