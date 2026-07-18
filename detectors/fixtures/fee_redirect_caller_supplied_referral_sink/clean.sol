// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

interface IERC20ReferralFee {
    function safeTransfer(address to, uint256 amount) external;
}

contract FeeRedirectCallerSuppliedReferralSinkClean {
    IERC20ReferralFee public immutable token;
    address public treasury;
    address public referralVault;
    uint256 public protocolFeeBps = 500;
    uint256 public constant BPS = 10000;
    uint256 public constant MAX_REFERRAL_SHARE_BPS = 1000;
    mapping(address => bool) public approvedReferral;

    constructor(IERC20ReferralFee token_, address treasury_, address referralVault_) {
        token = token_;
        treasury = treasury_;
        referralVault = referralVault_;
    }

    function buyPass(uint256 amount, address referral) external {
        uint256 protocolFee = (amount * protocolFeeBps) / BPS;
        uint256 referralFee = (protocolFee * MAX_REFERRAL_SHARE_BPS) / BPS;
        uint256 treasuryFee = protocolFee - referralFee;
        address referralSink = approvedReferral[referral] ? referral : referralVault;

        token.safeTransfer(treasury, treasuryFee);
        token.safeTransfer(referralSink, referralFee);
    }
}
