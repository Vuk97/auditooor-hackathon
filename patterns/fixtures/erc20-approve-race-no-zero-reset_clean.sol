// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function approve(address, uint256) external returns (bool);
}

contract ApproveRaceClean {
    IERC20 public immutable token;
    address public immutable spender;

    constructor(address t, address s) { token = IERC20(t); spender = s; }

    // Detector MUST NOT fire: explicit zero-reset precedes the new allowance.
    function setAllowance(uint256 amount) external {
        token.approve(spender, 0);
        token.approve(spender, amount);
    }
}
