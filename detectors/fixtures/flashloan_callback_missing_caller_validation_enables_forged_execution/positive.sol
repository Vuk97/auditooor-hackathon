// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20FlashloanCallbackPositive {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract FlashloanCallbackMissingCallerValidationPositive {
    address public immutable POOL;
    uint256 public lastAmount;

    constructor(address pool) {
        POOL = pool;
    }

    function executeOperation(
        address asset,
        uint256 amount,
        uint256 fee,
        address initiator,
        bytes calldata params
    ) external returns (bool) {
        initiator;
        params;
        lastAmount = amount + fee;
        IERC20FlashloanCallbackPositive(asset).transfer(address(0xBEEF), amount);
        return true;
    }
}
