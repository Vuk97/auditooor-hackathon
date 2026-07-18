// SPDX-License-Identifier: MIT
// Detector MUST NOT fire: the externally callable deposit is guarded.
pragma solidity ^0.8.20;

interface IERC1155Receiver {
    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external returns (bytes4);
}

interface IERC1155 {
    function safeTransferFrom(address, address, uint256, uint256, bytes calldata) external;
}

abstract contract ReentrancyGuard {
    uint256 private _status = 1;

    modifier nonReentrant() {
        require(_status != 2, "REENTRANT");
        _status = 2;
        _;
        _status = 1;
    }
}

contract CallbackReentrancyNoGuardClean is IERC1155Receiver, ReentrancyGuard {
    uint256 public balance;
    IERC1155 public token;

    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external pure returns (bytes4)
    {
        return this.onERC1155Received.selector;
    }

    function deposit(uint256 id, uint256 amount) external nonReentrant {
        token.safeTransferFrom(msg.sender, address(this), id, amount, "");
        balance += amount;
    }

    function depositCEI(uint256 id, uint256 amount) external {
        balance += amount;
        token.safeTransferFrom(msg.sender, address(this), id, amount, "");
    }
}

interface IPreLiquidationCallbackLike {
    function onPreLiquidate(uint256 repaidAssets, bytes calldata data) external;
}

interface IERC20Like {
    function safeTransferFrom(address from, address to, uint256 amount) external;
}

contract CallbackBeforeSettlementClean is ReentrancyGuard {
    address public loanToken;

    function onMorphoRepay(uint256 repaidAssets, bytes calldata callbackData) external nonReentrant {
        (address liquidator, bytes memory data) = abi.decode(callbackData, (address, bytes));

        IERC20Like(loanToken).safeTransferFrom(liquidator, address(this), repaidAssets);

        IPreLiquidationCallbackLike(liquidator).onPreLiquidate(repaidAssets, data);
    }
}
