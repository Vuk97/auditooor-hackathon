// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 { function transfer(address, uint256) external returns (bool); }

contract FlashCallbackClean {
    IERC20 public debtToken;
    address public pool;

    // CLEAN: gate on msg.sender == pool AND initiator == address(this)
    function executeOperation(
        address[] calldata, uint256[] calldata amounts, uint256[] calldata, address initiator, bytes calldata
    ) external returns (bool) {
        require(msg.sender == pool, "not pool");
        require(initiator == address(this), "initiator");
        debtToken.transfer(tx.origin, amounts[0]);
        return true;
    }
}
