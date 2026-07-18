// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Clean variant: every entry point cites one of the expected guards
// (`lastReferrerChange` cooldown, `referralCap`, `lastClaim` gate, or
// a `block.timestamp >` comparison). Each guard matches the
// detector's negated regex and suppresses the finding.
contract ReferrerRewardDrainPermissionlessClean {
    mapping(address => address) public referrer;
    mapping(address => uint256) public lastReferrerChange;
    mapping(address => uint256) public referrals;
    mapping(address => uint256) public lastClaim;
    uint256 public feePool;
    uint256 public constant REFERRAL_CAP = 1_000 ether;
    uint256 public constant REFERRER_COOLDOWN = 7 days;
    uint256 public constant CLAIM_INTERVAL = 1 days;

    // CLEAN: cooldown on referrer rotation and self-referral guard.
    function setReferrer(address ref) external {
        require(
            block.timestamp > lastReferrerChange[msg.sender] + REFERRER_COOLDOWN,
            "cooldown"
        );
        require(ref != msg.sender, "self");
        referrer[msg.sender] = ref;
        lastReferrerChange[msg.sender] = block.timestamp;
    }

    // CLEAN: per-referrer receipts capped at referralCap.
    function _payReferrer(address trader, uint256 fee) external {
        address r = referrer[trader];
        require(referrals[r] + fee / 10 <= REFERRAL_CAP, "referralCap");
        referrals[r] += fee / 10;
        feePool -= fee / 10;
    }

    // CLEAN: lastClaim gate enforces a per-epoch bound on extraction.
    function claimReferralFee(address to) external {
        require(block.timestamp > lastClaim[msg.sender] + CLAIM_INTERVAL, "wait");
        lastClaim[msg.sender] = block.timestamp;
        uint256 amount = referrals[msg.sender];
        referrals[msg.sender] = 0;
        to;
        amount;
    }
}
