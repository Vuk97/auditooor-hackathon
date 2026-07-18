// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DestructiveSinkTokenClean {
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    function burnFrom(address account, uint256 amount) external {
        require(account != address(0), "burn from zero address");
        uint256 allowed = allowance[account][msg.sender];
        if (allowed != type(uint256).max) {
            allowance[account][msg.sender] = allowed - amount;
        }
        balances[account] -= amount;
        totalSupply -= amount;
    }
}

contract DestructiveSinkTokenCustomErrorClean {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    error AddressCannotBeZero();

    function burn(address account, uint256 amount) external {
        if (account == address(0)) revert AddressCannotBeZero();
        balances[account] -= amount;
        totalSupply -= amount;
    }
}

contract DestructiveSinkTokenModifierClean {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    modifier nonZeroAddress(address account) {
        require(account != address(0), "zero address");
        _;
    }

    function burn(address account, uint256 amount) external nonZeroAddress(account) {
        balances[account] -= amount;
        totalSupply -= amount;
    }
}

contract PlainTransferRecipientClean {
    mapping(address => uint256) public balances;

    function transfer(address recipient, uint256 amount) external returns (bool) {
        balances[msg.sender] -= amount;
        balances[recipient] += amount;
        return true;
    }
}

contract DestructiveSinkVotesClean {
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
        require(delegatee != address(0), "ZERO_DELEGATEE");
        _delegate(msg.sender, delegatee);
    }

    function delegateBySig(address delegatee, uint256 nonce, uint256 expiry, uint8 v, bytes32 r, bytes32 s) external {
        require(delegatee != address(0), "ZERO_DELEGATEE");
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
