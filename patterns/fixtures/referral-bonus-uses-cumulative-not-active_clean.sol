// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

// CLEAN: upline credit gated on activeBalance (current principal) not
// on totalInvested. Withdraws revoke the team-count contribution.
contract ReferralPoolClean {
    IERC20 public token;
    mapping(address => uint256) public totalInvested;
    mapping(address => uint256) public activeBalance;     // current principal
    mapping(address => bool) public isActive;
    mapping(address => address) public referrer;
    mapping(address => uint256) public teamCount;
    mapping(address => uint256) public bonusAccrued;

    constructor(IERC20 _token) { token = _token; }

    function harvestHoney(uint256 planId, uint256 amount, address upline) external {
        token.transferFrom(msg.sender, address(this), amount);
        totalInvested[msg.sender] += amount;
        activeBalance[msg.sender] += amount;
        if (referrer[msg.sender] == address(0) && upline != address(0)) {
            referrer[msg.sender] = upline;
        }
        _refreshUpline(msg.sender);
    }

    function _refreshUpline(address who) internal {
        address up = referrer[who];
        bool nowActive = activeBalance[who] >= 10 ether;
        if (nowActive && !isActive[who]) {
            isActive[who] = true;
            while (up != address(0)) {
                teamCount[up] += 1;
                bonusAccrued[up] += 1 ether;
                up = referrer[up];
            }
        } else if (!nowActive && isActive[who]) {
            isActive[who] = false;
            while (up != address(0)) {
                teamCount[up] -= 1;
                up = referrer[up];
            }
        }
    }

    function withdraw(uint256 amount) external {
        require(activeBalance[msg.sender] >= amount, "no bal");
        activeBalance[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
        _refreshUpline(msg.sender);
    }

    function collectRefBonus() external {
        uint256 amt = bonusAccrued[msg.sender];
        bonusAccrued[msg.sender] = 0;
        token.transfer(msg.sender, amt);
    }
}
