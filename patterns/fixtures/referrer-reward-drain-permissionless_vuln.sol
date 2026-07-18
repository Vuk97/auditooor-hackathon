// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal referral-reward contract. The caller designates their own
// referrer (address param), the contract credits fees to that address,
// and anyone can claim accumulated referrer rewards. No cap, no
// cooldown, no pointer-stability check. This is the C0004 drain shape.
contract ReferrerRewardDrainPermissionlessVuln {
    mapping(address => address) public referrer;
    mapping(address => uint256) public referrals;
    uint256 public feePool;

    // VULN: caller can set any address (including a wallet they
    // control) as their referrer with no cooldown or self-ref guard.
    function setReferrer(address ref) external {
        referrer[msg.sender] = ref;
    }

    // VULN: pays referrer a percentage of the trade fee with no cap
    // on cumulative payouts to a single referrer.
    function _payReferrer(address trader, uint256 fee) external {
        address r = referrer[trader];
        if (r != address(0)) {
            referrals[r] += fee / 10;
            feePool -= fee / 10;
        }
    }

    // VULN: anyone can sweep their accumulated referral rewards with
    // no lastClaim gate, no time-lock, no cap.
    function claimReferralFee(address to) external {
        uint256 amount = referrals[msg.sender];
        referrals[msg.sender] = 0;
        // transfer(to, amount) in a real contract.
        to;
        amount;
    }
}
