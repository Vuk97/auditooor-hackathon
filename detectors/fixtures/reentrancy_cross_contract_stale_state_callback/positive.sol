// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPreLiquidationCallbackLift {
    function onPreLiquidate(uint256 repaidAssets, bytes calldata data) external;
}

interface ITokenLift {
    function safeTransfer(address to, uint256 amount) external;
    function safeTransferFrom(address from, address to, uint256 amount) external;
}

interface ISettlementAdapterLift {
    function onSettle(address user, uint256 amount, bytes calldata data) external;
}

contract PreLiquidationCallbackBeforePaymentLift {
    ITokenLift public loanToken;

    function onMorphoRepay(uint256 repaidAssets, bytes calldata callbackData) external {
        (address liquidator, bytes memory data) = abi.decode(callbackData, (address, bytes));

        IPreLiquidationCallbackLift(liquidator).onPreLiquidate(repaidAssets, data);

        loanToken.safeTransferFrom(liquidator, address(this), repaidAssets);
    }
}

contract TokenHookBeforeDepositAccountingLift {
    ITokenLift public asset;
    mapping(address => uint256) public balances;
    uint256 public totalAccounted;

    function deposit(uint256 assets) external {
        asset.safeTransferFrom(msg.sender, address(this), assets);

        balances[msg.sender] += assets;
        totalAccounted += assets;
    }
}

contract AdapterCallbackBeforeStatusLift {
    ISettlementAdapterLift public adapter;
    mapping(address => uint256) public settledAmount;
    mapping(address => bool) public finalized;

    function settle(address user, uint256 amount, bytes calldata data) external {
        adapter.onSettle(user, amount, data);

        settledAmount[user] += amount;
        finalized[user] = true;
    }
}
