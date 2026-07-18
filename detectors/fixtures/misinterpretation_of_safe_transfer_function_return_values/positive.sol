// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

library SafeTransferStatusShim {
    function safeTransfer(IERC20 token, address to, uint256 amount) internal returns (bool) {
        return token.transfer(to, amount);
    }
}

contract MisinterpretationOfSafeTransferFunctionReturnValuesPositive {
    using SafeTransferStatusShim for IERC20;

    mapping(address => uint256) public released;

    function sweep(address token, address to, uint256 amount) external {
        bool ok = IERC20(token).safeTransfer(to, amount);
        require(ok, "safe transfer failed");
        released[to] += amount;
    }
}
