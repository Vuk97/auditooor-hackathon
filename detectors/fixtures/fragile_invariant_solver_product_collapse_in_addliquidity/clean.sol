// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FragileInvariantSolverProductCollapseInAddLiquidityClean {
    uint256 internal amp = 10;
    uint256 internal prevSupply;

    function addLiquidity(uint256[2] memory amounts) external returns (uint256 minted) {
        _checkBootstrapProductGuard(amounts);
        uint256 d = _calcD(amounts);
        if (prevSupply == 0) {
            prevSupply = d;
            return d;
        }
        minted = d - prevSupply;
        prevSupply = d;
    }

    function _checkBootstrapProductGuard(uint256[2] memory amounts) internal view {
        uint256 prod = amounts[0] * amounts[1];
        require(prevSupply != 0 || prod != 0, "bootstrap/product guard");
    }

    function _calcD(uint256[2] memory amounts) internal view returns (uint256 d) {
        uint256 sum = amounts[0] + amounts[1];
        uint256 prod = amounts[0] * amounts[1];
        d = sum == 0 ? 1 : sum;
        for (uint256 i = 0; i < 2; ++i) {
            d = (d * sum) / prod;
        }
        return (amp * sum) - (d * prod);
    }
}
