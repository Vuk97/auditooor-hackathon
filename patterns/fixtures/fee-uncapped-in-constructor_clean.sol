// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FeeClean {
    uint256 public constant MAX_FEE = 1000;
    uint256 public fee;
    address public owner;

    constructor(uint256 _fee) {
        require(_fee <= MAX_FEE, "fee too high");
        fee = _fee;
        owner = msg.sender;
    }

    function setFee(uint256 _fee) external {
        require(msg.sender == owner, "not owner");
        require(_fee <= MAX_FEE, "fee too high");
        fee = _fee;
    }
}
