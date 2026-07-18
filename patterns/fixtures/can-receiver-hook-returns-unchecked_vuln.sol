// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IFlashBorrower {
    function onFlashLoan(address initiator, address token, uint256 amount, uint256 fee, bytes calldata data)
        external returns (bytes32);
}

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

contract FlashVuln {
    IERC20 public token;

    // BUG: calls onFlashLoan but discards the return value.
    function flashLoan(IFlashBorrower receiver, uint256 amount, bytes calldata data) external {
        token.transfer(address(receiver), amount);
        receiver.onFlashLoan(msg.sender, address(token), amount, 0, data);
        token.transferFrom(address(receiver), address(this), amount);
    }
}
