// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SignedActionClean {
    mapping(bytes32 => bool) public used;

    function claim(address to, uint256 amount, uint256 nonce, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        require(block.timestamp <= deadline, "expired");
        bytes32 h = keccak256(abi.encode(to, amount, nonce, deadline));
        address signer = ecrecover(h, v, r, s);
        require(signer == to, "bad sig");
        require(!used[h], "used");
        used[h] = true;
    }
}
