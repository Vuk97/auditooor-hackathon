// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SigAuthVuln {
    mapping(address => uint256) public balances;

    // VULN: signature lacks replay protection -- no per-user counter or time bound
    function withdrawWithSig(address user, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 hash = keccak256(abi.encodePacked(user, amount));
        address recovered = ecrecover(hash, v, r, s);
        require(recovered == user, "bad sig");
        balances[user] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
