// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function approve(address, uint256) external returns (bool);
}

contract ApproveRaceVuln {
    IERC20 public immutable token;
    address public immutable spender;

    constructor(address t, address s) { token = IERC20(t); spender = s; }

    // Detector MUST fire: non-zero approve issued without a prior zero reset
    // and without any SafeERC20 / forceApprove wrapper.
    function setAllowance(uint256 amount) external {
        token.approve(spender, amount);
    }
}
