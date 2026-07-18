// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

// Fixture: fixed — permit() wrapped in try/catch, griefing impossible.
// Source: aave-dao/aave-v3-origin@3bdd8c7 (Sherlock audit fix)

interface IERC20Permit {
    function permit(address owner, address spender, uint256 value, uint256 deadline,
                    uint8 v, bytes32 r, bytes32 s) external;
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract WrappedTokenGateway {
    IERC20Permit public aWETH;

    // FIXED: try/catch swallows already-used-nonce revert; transferFrom still enforces allowance
    function withdrawETHWithPermit(
        uint256 amount,
        uint256 deadline,
        uint8 permitV,
        bytes32 permitR,
        bytes32 permitS
    ) external {
        uint256 amountToWithdraw = amount;

        // Safe: if permit already consumed, catch the revert; transferFrom validates allowance
        try aWETH.permit(msg.sender, address(this), amount, deadline, permitV, permitR, permitS)
        {} catch {}
        aWETH.transferFrom(msg.sender, address(this), amountToWithdraw);
    }
}
