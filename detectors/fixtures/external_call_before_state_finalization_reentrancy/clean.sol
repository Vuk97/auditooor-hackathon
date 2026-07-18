// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPreLiquidationCallbackReplay {
    function onPreLiquidate(uint256 repaidAssets, bytes calldata data) external;
}

interface IFlashBorrowerReplay {
    function onFlashLoan(address asset, uint256 amount, uint256 fee, bytes calldata data) external;
}

interface IERC20Replay {
    function safeTransfer(address to, uint256 amount) external;
    function safeTransferFrom(address from, address to, uint256 amount) external;
}

abstract contract ReentrancyGuardReplay {
    uint256 private _status = 1;

    modifier nonReentrant() {
        require(_status != 2, "REENTRANT");
        _status = 2;
        _;
        _status = 1;
    }
}

contract CallbackBeforePaymentGuarded is ReentrancyGuardReplay {
    IERC20Replay public loanToken;

    function onMorphoRepay(uint256 repaidAssets, bytes calldata callbackData) external nonReentrant {
        (address liquidator, bytes memory data) = abi.decode(callbackData, (address, bytes));

        IPreLiquidationCallbackReplay(liquidator).onPreLiquidate(repaidAssets, data);

        loanToken.safeTransferFrom(liquidator, address(this), repaidAssets);
    }
}

contract FlashCallbackAfterDebtReplay is ReentrancyGuardReplay {
    IERC20Replay public asset;
    uint256 public totalDebt;

    function flashLoan(address receiver, uint256 amount, bytes calldata data) external nonReentrant {
        uint256 fee = amount / 1000;

        totalDebt += fee;
        asset.safeTransfer(receiver, amount);
        IFlashBorrowerReplay(receiver).onFlashLoan(address(asset), amount, fee, data);
        asset.safeTransferFrom(receiver, address(this), amount + fee);
    }
}

contract TokenHookAfterBalanceReplay {
    IERC20Replay public asset;
    mapping(address => uint256) public balances;

    function deposit(uint256 assets) external {
        balances[msg.sender] += assets;

        asset.safeTransferFrom(msg.sender, address(this), assets);
    }
}
