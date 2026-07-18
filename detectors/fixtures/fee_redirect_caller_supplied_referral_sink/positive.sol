// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

interface IERC20ReferralFee {
    function safeTransfer(address to, uint256 amount) external;
}

contract FeeRedirectCallerSuppliedReferralSinkPositive {
    IERC20ReferralFee public immutable token;
    address public treasury;
    uint256 public protocolFeeBps = 500;
    uint256 public constant BPS = 10000;

    constructor(IERC20ReferralFee token_, address treasury_) {
        token = token_;
        treasury = treasury_;
    }

    function buyPass(uint256 amount, address referral) external {
        uint256 protocolFee = (amount * protocolFeeBps) / BPS;
        uint256 referralFee = protocolFee / 2;
        uint256 treasuryFee = protocolFee - referralFee;

        token.safeTransfer(treasury, treasuryFee);
        token.safeTransfer(referral, referralFee);
    }
}
