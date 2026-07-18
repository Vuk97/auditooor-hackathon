// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 { function transfer(address, uint256) external returns (bool); }

contract FlashCallbackVuln {
    IERC20 public debtToken;
    address public pool;

    // VULN: no msg.sender == pool check.
    function executeOperation(
        address[] calldata, uint256[] calldata amounts, uint256[] calldata, address, bytes calldata
    ) external returns (bool) {
        debtToken.transfer(tx.origin, amounts[0]); // trust-based post-loan swap
        return true;
    }
}
