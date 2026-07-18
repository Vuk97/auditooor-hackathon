// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

interface IFlashBorrower {
    function onFlashLoan(address asset, uint256 amount, uint256 fee) external returns (bytes32);
}

contract FlashloanNoiseControl {
    mapping(address => uint256) public debt;

    function flashLoan(address asset, address receiver, uint256 amount) external {
        uint256 fee = amount / 1000;
        IERC20(asset).transfer(receiver, amount);
        require(IFlashBorrower(receiver).onFlashLoan(asset, amount, fee) == keccak256("OK"), "callback");
        debt[receiver] += fee;
    }
}
