// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

library GlvDeposit {
    struct Data {
        bool marketTokenDeposit;
        address market;
        uint256 amount;
    }

    function isMarketTokenDeposit(Data memory self) internal pure returns (bool) {
        return self.marketTokenDeposit;
    }
}

library MarketUtils {
    function validateMaxPnl(address, uint256) internal pure {}
}

contract GlvDepositExecutorPositive {
    using GlvDeposit for GlvDeposit.Data;

    uint256 internal constant MAX_PNL_FACTOR_FOR_DEPOSITS = 1e30;
    uint256 internal minted;

    function executeGlvDeposit(GlvDeposit.Data memory deposit) external {
        if (deposit.isMarketTokenDeposit()) {
            MarketUtils.validateMaxPnl(deposit.market, MAX_PNL_FACTOR_FOR_DEPOSITS);
            _transferMarketTokens(deposit);
        } else {
            _buyMarketTokens(deposit);
        }

        _mintGlv(deposit.amount);
    }

    function _transferMarketTokens(GlvDeposit.Data memory deposit) internal {
        minted += deposit.amount;
    }

    function _buyMarketTokens(GlvDeposit.Data memory deposit) internal {
        minted += deposit.amount;
    }

    function _mintGlv(uint256 amount) internal {
        minted += amount;
    }
}
