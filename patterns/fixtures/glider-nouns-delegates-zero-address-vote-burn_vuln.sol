// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract NounsLikeVotesVuln {
    mapping(address => address) internal _delegates;
    mapping(address => uint256) public balances;
    mapping(address => uint96) public currentVotes;

    event DelegateChanged(address indexed delegator, address indexed from, address indexed to);

    // Nouns-style getter — returns account if stored delegate is zero
    // (implicit self-delegation).
    function delegates(address account) external view returns (address) {
        if (_delegates[account] == address(0)) {
            return account;
        }
        return _delegates[account];
    }

    // VULN: delegate() forwards to _delegate without rejecting a zero
    // delegatee. _moveDelegates decrements source and credits address(0),
    // burning votes.
    function delegate(address delegatee) external {
        _delegate(msg.sender, delegatee);
    }

    function delegateBySig(
        address delegatee,
        uint256 /*nonce*/,
        uint256 /*expiry*/,
        uint8 /*v*/, bytes32 /*r*/, bytes32 /*s*/
    ) external {
        // Attacker-controlled signature forces delegatee == address(0).
        _delegate(msg.sender, delegatee);
    }

    function _delegate(address delegator, address newDelegatee) internal {
        address old = _delegates[delegator];
        _delegates[delegator] = newDelegatee;
        uint256 amount = balances[delegator];
        _moveDelegates(old == address(0) ? delegator : old, newDelegatee, amount);
        emit DelegateChanged(delegator, old, newDelegatee);
    }

    function _moveDelegates(address src, address dst, uint256 amount) internal {
        if (src != dst && amount > 0) {
            if (src != address(0)) {
                currentVotes[src] -= uint96(amount);
            }
            // If dst == address(0), we never increment anywhere — votes burned.
            if (dst != address(0)) {
                currentVotes[dst] += uint96(amount);
            }
        }
    }
}
