// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

interface IERC20FeeRedirectCollector {
    function safeTransfer(address to, uint256 amount) external;
}

contract FeeRedirectUserControlledCollectorOrSinkPositive {
    IERC20FeeRedirectCollector public immutable token;
    address public owner;
    address public feeCollector;
    uint256 public accruedFee;

    constructor(IERC20FeeRedirectCollector token_, address collector_) {
        token = token_;
        owner = msg.sender;
        feeCollector = collector_;
    }

    function accrueProtocolFee(uint256 amount) external {
        accruedFee += amount;
    }

    function setFeeCollector(address newCollector) external {
        require(newCollector != address(0), "collector");
        feeCollector = newCollector;
    }

    function collectProtocolFees() external {
        uint256 feeAmount = accruedFee;
        require(feeAmount != 0, "no fee");
        accruedFee = 0;
        token.safeTransfer(feeCollector, feeAmount);
    }
}
