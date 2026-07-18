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

// CLEAN: every position-mutating external on the sibling adapter consults the
// companion exchange's pause flag before moving tokens. Emergency pause on
// CTFExchange now propagates correctly to redemption / split / merge paths.
contract CtfCollateralAdapter {
    IERC20 public immutable USDCE;
    IConditionalTokens public immutable CTF;
    address public immutable EXCHANGE;

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
        require(!IExchange(EXCHANGE).paused(), "PAUSED");
        CTF.redeemPositions(address(USDCE), parent, cond, sets);
        USDCE.transfer(msg.sender, amount);
    }

    function splitPosition(uint256 amount) external {
        require(!IExchange(EXCHANGE).paused(), "PAUSED");
        USDCE.transferFrom(msg.sender, address(this), amount);
    }
}
