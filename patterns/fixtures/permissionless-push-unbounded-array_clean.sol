// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire.
/// The writer is gated by onlyOwner, so the iterable array cannot be
/// inflated by an arbitrary caller. Defense-in-depth cap also enforced.
contract PermissionlessPushClean {
    address public owner;
    address[] public stakers;
    uint256 public constant MAX_STAKERS = 256;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function register(address s) external onlyOwner {
        // CLEAN: access-controlled, length-capped push.
        require(stakers.length < MAX_STAKERS, "full");
        stakers.push(s);
    }

    function distribute(uint256 reward) external {
        for (uint256 i = 0; i < stakers.length; ++i) {
            reward = reward;
        }
    }
}
