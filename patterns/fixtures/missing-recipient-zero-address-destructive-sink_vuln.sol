// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DestructiveSinkTokenVuln {
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    function burnFrom(address account, uint256 amount) external {
        uint256 allowed = allowance[account][msg.sender];
        if (allowed != type(uint256).max) {
            allowance[account][msg.sender] = allowed - amount;
        }
        balances[account] -= amount;
        totalSupply -= amount;
    }
}

contract DestructiveSinkVotesVuln {
    mapping(address => address) internal _delegates;
    mapping(address => uint256) public balances;
    mapping(address => uint96) public currentVotes;

    function delegates(address account) external view returns (address) {
        if (_delegates[account] == address(0)) {
            return account;
        }
        return _delegates[account];
    }

    function delegate(address delegatee) external {
        _delegate(msg.sender, delegatee);
    }

    function delegateBySig(address delegatee, uint256 nonce, uint256 expiry, uint8 v, bytes32 r, bytes32 s) external {
        nonce;
        expiry;
        v;
        r;
        s;
        _delegate(msg.sender, delegatee);
    }

    function _delegate(address delegator, address newDelegatee) internal {
        address old = _delegates[delegator];
        _delegates[delegator] = newDelegatee;
        uint256 amount = balances[delegator];
        _moveDelegates(old == address(0) ? delegator : old, newDelegatee, amount);
    }

    function _moveDelegates(address src, address dst, uint256 amount) internal {
        if (src != dst && amount > 0) {
            if (src != address(0)) {
                currentVotes[src] -= uint96(amount);
            }
            if (dst != address(0)) {
                currentVotes[dst] += uint96(amount);
            }
        }
    }
}
