// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

interface IERC20 {
    function safeTransfer(address to, uint256 amount) external;
}

contract FeeRedirectUserControlledSinkPositive {
    IERC20 public immutable token;
    address public treasury;
    uint256 public accruedFee;

    constructor(IERC20 token_, address treasury_) {
        token = token_;
        treasury = treasury_;
    }

    function accrueProtocolFee(uint256 amount) external {
        accruedFee += amount;
    }

    function withdrawProtocolFee(address feeRecipient) external {
        uint256 feeAmount = accruedFee;
        require(feeAmount != 0, "no fee");
        accruedFee = 0;
        token.safeTransfer(feeRecipient, feeAmount);
    }
}
