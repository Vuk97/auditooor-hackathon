// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: Protocol enforces slippage on the buy/mint side but forgets to
// apply the mirror guard on the sell/exit side. The sell-family names
// (sell, sellToken, exitPosition, closePosition, redeemForStable,
// _withdrawRewards) all invoke a router swap without any amountOutMin /
// minReceived / _minOut guard.

interface IRouter {
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory);
}

interface ICurvePool {
    function exchange(int128 i, int128 j, uint256 dx, uint256 minDy) external returns (uint256);
}

contract AsymmetricSlippageVuln {
    IRouter    public immutable router;
    ICurvePool public immutable pool;

    constructor(address _r, address _p) {
        router = IRouter(_r);
        pool   = ICurvePool(_p);
    }

    // CLEAN-LOOKING reference: buy-side forwards a minReceived. Included
    // to make the asymmetry with sell-side visible to the reader; the
    // detector should NOT fire on this function because its name is not
    // in the sell-family regex.
    function buyToken(uint256 amountIn, uint256 minReceived, address[] calldata path) external {
        router.swapExactTokensForTokens(amountIn, minReceived, path, msg.sender, block.timestamp);
    }

    // VULN 1: sellToken — exact sell-family name, router swap, no min.
    function sellToken(uint256 amountIn, address[] calldata path) external returns (uint256 out) {
        uint256[] memory amounts = router.swapExactTokensForTokens(
            amountIn, 0, path, msg.sender, block.timestamp
        );
        out = amounts[amounts.length - 1];
    }

    // VULN 2: exitPosition — position-manager sell-side, Curve exchange, no min.
    function exitPosition(uint256 amountIn) external returns (uint256 got) {
        got = pool.exchange(1, 0, amountIn, 0);
    }

    // VULN 3: redeemForStable — peg-vault sell side, router swap, no min.
    function redeemForStable(uint256 amountIn, address[] calldata path) external returns (uint256 out) {
        uint256[] memory amounts = router.swapExactTokensForTokens(
            amountIn, 0, path, msg.sender, block.timestamp
        );
        out = amounts[amounts.length - 1];
    }

    // VULN 4: _withdrawRewards — leaf helper exposed via external trigger,
    // explicitly named by the cluster. Pattern opts in to
    // include_leaf_helpers so this hit is preserved.
    function _withdrawRewards() external returns (uint256 out) {
        address[] memory path = new address[](2);
        uint256[] memory amounts = router.swapExactTokensForTokens(
            1e18, 0, path, address(this), block.timestamp
        );
        out = amounts[amounts.length - 1];
    }
}
