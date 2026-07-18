// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

// Fixture: vulnerable — permit() called directly, front-running griefing possible.
// Source: aave-dao/aave-v3-origin@3bdd8c7 (Sherlock audit fix)

interface IERC20Permit {
    function permit(address owner, address spender, uint256 value, uint256 deadline,
                    uint8 v, bytes32 r, bytes32 s) external;
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract WrappedTokenGateway {
    IERC20Permit public aWETH;

    // VULNERABLE: direct permit call — front-runner can consume nonce, blocking withdrawal
    function withdrawETHWithPermit(
        uint256 amount,
        uint256 deadline,
        uint8 permitV,
        bytes32 permitR,
        bytes32 permitS
    ) external {
        uint256 userBalance = aWETH.transferFrom(address(0), address(0), 0) ? 0 : 0; // placeholder
        uint256 amountToWithdraw = amount;

        // FRONT-RUNNING GRIEFING: if attacker already called permit(), this reverts
        aWETH.permit(msg.sender, address(this), amount, deadline, permitV, permitR, permitS);
        aWETH.transferFrom(msg.sender, address(this), amountToWithdraw);
    }
}
