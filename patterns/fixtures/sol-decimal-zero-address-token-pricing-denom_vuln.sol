// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 { function decimals() external view returns (uint8); }

contract DecimalDenomVuln {
    function shares(address token, uint256 amount) external view returns (uint256) {
        uint8 d = IERC20(token).decimals();
        return amount * 1e18 / 10**d;
    }
}
