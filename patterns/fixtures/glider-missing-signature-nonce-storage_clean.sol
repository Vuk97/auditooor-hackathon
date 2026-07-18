// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SigAuthClean {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public nonces;

    function withdrawWithSig(address user, uint256 amount, uint256 nonce, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        require(block.timestamp <= deadline, "expired");
        require(nonce == nonces[user], "bad nonce");
        bytes32 hash = keccak256(abi.encodePacked(user, amount, nonce, deadline));
        address recovered = ecrecover(hash, v, r, s);
        require(recovered == user, "bad sig");
        nonces[user] += 1;
        balances[user] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
