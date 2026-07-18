// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (d): a loop bounded by an attacker-growable state array `.length` with
// a state-write effect inside the body (unbounded_loop_suspect=TRUE). Anyone can
// grow `users` via join(), so the loop's gas cost is attacker-controlled.
contract LoopAttackerGrowableSuspect {
    address[] public users;
    mapping(address => uint256) public reward;

    function join() external {
        users.push(msg.sender);   // attacker-growable public surface
    }

    // UNBOUNDED-LOOP: bound is `users.length`, attacker-growable. // LOOP-TARGET
    function distribute() external {
        for (uint256 i = 0; i < users.length; i++) {
            reward[users[i]] += 1;   // EFFECT inside the loop body
        }
    }
}
