// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract ProtocolFeeVaultClean {
    IERC20 public immutable token;
    address public treasury;
    uint256 public accruedFee;

    constructor(IERC20 token_, address treasury_) {
        token = token_;
        treasury = treasury_;
    }

    function accrue(uint256 amount) external {
        accruedFee += amount;
    }

    function withdrawFee() external {
        uint256 fee = accruedFee;
        require(fee != 0, "no fees");
        accruedFee = 0;
        token.transfer(treasury, fee);
    }
}
