// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract IsolateClean {
    mapping(uint256 => uint256) public amount;
    mapping(uint256 => address) public lockerAddr;

    function erc721Decrease(uint256 id, uint256 amt) external {
        amount[id] -= amt;
        if (amount[id] == 0) {
            lockerAddr[id] = address(0);
        }
    }
}
