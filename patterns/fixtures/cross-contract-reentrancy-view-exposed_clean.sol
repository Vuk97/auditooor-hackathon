// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Clean: contract has NO callback-receiving surface (no onERC*/IFlashLoan/.call/
// callback/onHook), so the contract-level precondition fails and the view is
// safe. This verifies the precondition gating works: even though the view
// still reads reserve/supply state, without a callback vector there is no
// read-only reentrancy exposure.

contract ReadOnlyReentrancyClean {
    uint256 internal reserve0;
    uint256 internal reserve1;
    uint256 internal _totalSupply;
    mapping(address => uint256) internal _balance;

    // Plain mutating function, NO external call, NO hook receiver.
    function deposit(uint256 amt) external {
        reserve0 += amt;
        _totalSupply += amt;
        _balance[msg.sender] += amt;
    }

    function withdraw(uint256 amt) external {
        require(_balance[msg.sender] >= amt);
        reserve0 -= amt;
        _totalSupply -= amt;
        _balance[msg.sender] -= amt;
    }

    // Views read the same state but no callback vector exists in this contract.
    function getReserves() external view returns (uint256, uint256) {
        return (reserve0, reserve1);
    }

    function totalSupply() external view returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address a) external view returns (uint256) {
        return _balance[a];
    }
}
