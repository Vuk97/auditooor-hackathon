// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Metadata { function decimals() external view returns (uint8); }

contract DecimalMultClean {
    IERC20Metadata public token;

    // CLEAN: branches on decimals > 18.
    function handleDeposit(uint256 amount) external view returns (uint256) {
        uint8 d = token.decimals();
        if (d > 18) {
            return amount / (10 ** (d - 18));
        } else {
            return amount * (10 ** (18 - d));
        }
    }
}
