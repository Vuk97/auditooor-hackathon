// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IConditionalTokens {
    function redeemPositions(address collateral, bytes32 parent, bytes32 cond, uint256[] calldata sets) external;
}

interface IExchange {
    function paused() external view returns (bool);
}

// VULN: CtfCollateralAdapter exposes position-mutating ops (redeemPositions,
// splitPosition) that move tokens, but NEVER reads the companion exchange's
// pause flag and carries no pause modifier of its own. When the exchange is
// paused via CTFExchange.pauseTrading(), this adapter still happily moves
// USDC/USDC.e — emergency pause is bypassable.
contract CtfCollateralAdapter {
    IERC20 public immutable USDCE;
    IConditionalTokens public immutable CTF;
    address public immutable EXCHANGE; // companion CTFExchange — never consulted

    constructor(address usdce, address ctf, address exchange) {
        USDCE = IERC20(usdce);
        CTF = IConditionalTokens(ctf);
        EXCHANGE = exchange;
    }

    function redeemPositions(
        bytes32 parent,
        bytes32 cond,
        uint256[] calldata sets,
        uint256 amount
    ) external {
        // VULN: no `require(!IExchange(EXCHANGE).paused(), "PAUSED")`.
        CTF.redeemPositions(address(USDCE), parent, cond, sets);
        USDCE.transfer(msg.sender, amount);
    }

    function splitPosition(uint256 amount) external {
        // VULN: no pause check; mints positions even while exchange is paused.
        USDCE.transferFrom(msg.sender, address(this), amount);
    }
}
