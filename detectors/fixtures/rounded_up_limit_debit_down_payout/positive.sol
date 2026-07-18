// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

library MathLib {
    enum Rounding {
        Down,
        Up
    }
}

interface IBalanceSheet {
    function unreserve(address token, address owner, uint128 amount) external;
    function withdraw(address token, address receiver, uint128 amount) external;
}

contract AsyncVaultRoundedDebit {
    struct AsyncInvestmentState {
        uint128 maxWithdraw;
        uint128 redeemPrice;
    }

    mapping(address => AsyncInvestmentState) public investments;
    IBalanceSheet public balanceSheet;
    address public asset;

    function redeem(uint256 shares, address receiver) public returns (uint256 assets) {
        AsyncInvestmentState storage state = investments[msg.sender];

        uint128 shares_ = uint128(shares);
        uint128 assetsUp = _shareToAssetAmount(shares_, state.redeemPrice, MathLib.Rounding.Up);
        uint128 assetsDown = _shareToAssetAmount(shares_, state.redeemPrice, MathLib.Rounding.Down);

        _processRedeem(state, assetsUp, assetsDown, receiver);
        assets = uint256(assetsDown);
    }

    function _processRedeem(
        AsyncInvestmentState storage state,
        uint128 assetsUp,
        uint128 assetsDown,
        address receiver
    ) internal {
        require(assetsUp <= state.maxWithdraw, "limit");
        state.maxWithdraw = state.maxWithdraw - assetsUp;

        if (assetsDown > 0) {
            balanceSheet.unreserve(asset, address(this), assetsDown);
            balanceSheet.withdraw(asset, receiver, assetsDown);
        }
    }

    function _shareToAssetAmount(uint128 shares, uint128 price, MathLib.Rounding rounding)
        internal
        pure
        returns (uint128)
    {
        uint256 raw = uint256(shares) * uint256(price);
        if (rounding == MathLib.Rounding.Up && raw % 1e18 != 0) return uint128(raw / 1e18 + 1);
        return uint128(raw / 1e18);
    }
}
