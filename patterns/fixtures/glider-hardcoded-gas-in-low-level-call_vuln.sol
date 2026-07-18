// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract HardcodedGasVuln {
    uint256 public balance;

    constructor() {
        balance = 100 ether;
    }

    function deposit() external payable {
        balance += msg.value;
    }

    function withdraw(address payable to, uint256 amount) external {
        to.transfer(amount);
        balance -= amount;
    }

    function sendViaCall(address payable to, uint256 amount) external {
        (bool success, ) = to.call{gas: 5000, value: amount}("");
        require(success, "call failed");
        balance -= amount;
    }

    function forwardTo(address target, bytes calldata data) external {
        (bool success, ) = target.call{gas: 10000}(data);
        require(success, "forward failed");
    }
}