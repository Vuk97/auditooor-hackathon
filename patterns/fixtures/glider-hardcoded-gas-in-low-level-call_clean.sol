// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract HardcodedGasClean {
    uint256 public balance;

    constructor() {
        balance = 100 ether;
    }

    function deposit() external payable {
        balance += msg.value;
    }

    function withdrawSafe(address payable to, uint256 amount) external {
        (bool success, ) = to.call{value: amount}("");
        require(success, "transfer failed");
        balance -= amount;
    }

    function forwardWithGuard(address target, bytes calldata data) external {
        (bool success, ) = target.call(data);
        require(success, "forward failed");
    }
}