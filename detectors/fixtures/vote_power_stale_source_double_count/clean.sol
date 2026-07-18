// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VoteSourceArrayReassignmentClean {
    mapping(uint256 => address) public delegateOfSource;
    mapping(address => uint256[]) public delegateSources;
    mapping(uint256 => uint256) public sourceVotingPower;

    function changeDelegate(uint256 sourceId, address newDelegate) external {
        address currentDelegate = delegateOfSource[sourceId];
        if (currentDelegate != address(0)) {
            _removeDelegation(currentDelegate, sourceId);
        }
        delegateOfSource[sourceId] = newDelegate;
        delegateSources[newDelegate].push(sourceId);
    }

    function _removeDelegation(address oldDelegate, uint256 sourceId) internal {
        uint256[] storage sources = delegateSources[oldDelegate];
        for (uint256 i = 0; i < sources.length; i++) {
            if (sources[i] == sourceId) {
                sources[i] = sources[sources.length - 1];
                sources.pop();
                return;
            }
        }
    }

    function votingPowerOf(address delegatee) external view returns (uint256 total) {
        uint256[] storage sources = delegateSources[delegatee];
        for (uint256 i = 0; i < sources.length; i++) {
            total += sourceVotingPower[sources[i]];
        }
    }
}

contract VotePowerLedgerReassignmentClean {
    mapping(address => address) public delegateOf;
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public delegateVotePower;

    function seed(address account, uint256 amount) external {
        balanceOf[account] = amount;
    }

    function setDelegate(address to) external {
        address previousDelegate = delegateOf[msg.sender];
        uint256 units = balanceOf[msg.sender];

        if (previousDelegate != address(0)) {
            delegateVotePower[previousDelegate] -= units;
        }

        delegateOf[msg.sender] = to;
        delegateVotePower[to] += units;
    }
}
