// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — detector MUST fire.
/// External `register` has no access control and pushes the caller into an
/// iterable storage array. An attacker can cheaply inflate `stakers.length`
/// until any downstream iterator (distribute, snapshot, tally) exceeds the
/// block gas limit and reverts permanently.
contract PermissionlessPushVuln {
    address[] public stakers;

    function register(address s) external {
        // VULN: no onlyOwner / onlyRoles modifier; any caller can push.
        stakers.push(s);
    }

    function distribute(uint256 reward) external {
        // The iterator that becomes DoS-able once `stakers` is inflated.
        for (uint256 i = 0; i < stakers.length; ++i) {
            // elided: transfer(stakers[i], reward)
            reward = reward;
        }
    }
}
