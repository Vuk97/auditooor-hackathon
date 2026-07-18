// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Metadata { function decimals() external view returns (uint8); }

contract DecimalMultVuln {
    IERC20Metadata public token;

    // VULN: assumes decimals <= 18; a 24-decimal token reverts here.
    function handleDeposit(uint256 amount) external view returns (uint256) {
        uint8 d = token.decimals();
        return amount * 10 ** (18 - d);
    }
}
