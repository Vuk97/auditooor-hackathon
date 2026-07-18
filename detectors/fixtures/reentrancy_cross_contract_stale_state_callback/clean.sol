// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPreLiquidationCallbackLiftClean {
    function onPreLiquidate(uint256 repaidAssets, bytes calldata data) external;
}

interface ITokenLiftClean {
    function safeTransfer(address to, uint256 amount) external;
    function safeTransferFrom(address from, address to, uint256 amount) external;
}

interface ISettlementAdapterLiftClean {
    function onSettle(address user, uint256 amount, bytes calldata data) external;
}

abstract contract ReentrancyGuardLiftClean {
    uint256 private _status = 1;

    modifier nonReentrant() {
        require(_status != 2, "REENTRANT");
        _status = 2;
        _;
        _status = 1;
    }
}

contract PreLiquidationCallbackGuardedLiftClean is ReentrancyGuardLiftClean {
    ITokenLiftClean public loanToken;

    function onMorphoRepay(uint256 repaidAssets, bytes calldata callbackData) external nonReentrant {
        (address liquidator, bytes memory data) = abi.decode(callbackData, (address, bytes));

        IPreLiquidationCallbackLiftClean(liquidator).onPreLiquidate(repaidAssets, data);

        loanToken.safeTransferFrom(liquidator, address(this), repaidAssets);
    }
}

contract TokenHookAfterDepositAccountingLiftClean {
    ITokenLiftClean public asset;
    mapping(address => uint256) public balances;
    uint256 public totalAccounted;

    function deposit(uint256 assets) external {
        balances[msg.sender] += assets;
        totalAccounted += assets;

        asset.safeTransferFrom(msg.sender, address(this), assets);
    }
}

contract AdapterCallbackAfterStatusLiftClean {
    ISettlementAdapterLiftClean public adapter;
    mapping(address => uint256) public settledAmount;
    mapping(address => bool) public finalized;

    function settle(address user, uint256 amount, bytes calldata data) external {
        settledAmount[user] += amount;
        finalized[user] = true;

        adapter.onSettle(user, amount, data);
    }
}
