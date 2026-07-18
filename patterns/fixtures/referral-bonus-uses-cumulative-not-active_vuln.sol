// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

// VULN: Grizzifi-style referral program. upline team-count is driven
// by totalInvested — a monotonic counter not decreased on withdraw.
// Sybil referees that deposit-then-withdraw still credit the upline.
contract ReferralPoolVuln {
    IERC20 public token;
    mapping(address => uint256) public totalInvested;     // cumulative, never decreases
    mapping(address => uint256) public balance;           // current principal
    mapping(address => address) public referrer;
    mapping(address => uint256) public teamCount;
    mapping(address => uint256) public bonusAccrued;

    constructor(IERC20 _token) { token = _token; }

    function harvestHoney(uint256 planId, uint256 amount, address upline) external {
        token.transferFrom(msg.sender, address(this), amount);
        totalInvested[msg.sender] += amount;
        balance[msg.sender] += amount;
        if (referrer[msg.sender] == address(0) && upline != address(0)) {
            referrer[msg.sender] = upline;
        }
        _incrementUplineTeamCount(msg.sender);
    }

    function _incrementUplineTeamCount(address who) internal {
        address up = referrer[who];
        while (up != address(0)) {
            // BUG: counts totalInvested, which stays after withdrawal
            if (totalInvested[who] >= 10 ether) {
                teamCount[up] += 1;
                bonusAccrued[up] += 1 ether;
            }
            up = referrer[up];
        }
    }

    function withdraw(uint256 amount) external {
        require(balance[msg.sender] >= amount, "no bal");
        balance[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
        // NOTE: totalInvested is NOT decremented here
    }

    function collectRefBonus() external {
        uint256 amt = bonusAccrued[msg.sender];
        bonusAccrued[msg.sender] = 0;
        token.transfer(msg.sender, amt);
    }
}
