// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire.
/// Two independent safe shapes are provided, both of which the v1
/// regex-based predicate accepts as clean:
///
///   depositNoFee   — no fee adjustment in the body at all, so the
///                    "computes a fee" positive surface is absent.
///   depositEmitNet — still takes a fee, but emits a non-`amount`-named
///                    variable (netCredited), so the "emits an amount-
///                    named arg first" positive surface is absent.
contract EventWrongParamClean {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    event Deposit(address indexed user, uint256 credited);

    // Shape #1: no fee computation in the function body.
    function depositNoFee(uint256 value) external {
        balances[msg.sender] += value;
        totalSupply += value;
        emit Deposit(msg.sender, value);
    }

    // Shape #2: fee is computed, but the event carries the final written
    // variable under a distinct name (`netCredited`) so the event schema
    // matches the state mutation and off-chain indexers reconcile.
    function depositEmitNet(uint256 value) external {
        uint256 charge = value / 100;
        uint256 netCredited = value - charge;

        balances[msg.sender] += netCredited;
        totalSupply += netCredited;

        emit Deposit(msg.sender, netCredited);
    }
}
