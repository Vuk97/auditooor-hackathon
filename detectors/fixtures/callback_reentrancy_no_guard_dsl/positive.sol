// SPDX-License-Identifier: MIT
// Detector MUST fire: external token callback can re-enter before balance updates.
pragma solidity ^0.8.20;

interface IERC1155Receiver {
    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external returns (bytes4);
}

interface IERC1155 {
    function safeTransferFrom(address, address, uint256, uint256, bytes calldata) external;
}

contract CallbackReentrancyNoGuardPositive is IERC1155Receiver {
    uint256 public balance;
    IERC1155 public token;

    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external pure returns (bytes4)
    {
        return this.onERC1155Received.selector;
    }

    function deposit(uint256 id, uint256 amount) external {
        token.safeTransferFrom(msg.sender, address(this), id, amount, "");
        balance += amount;
    }
}

interface IPreLiquidationCallbackLike {
    function onPreLiquidate(uint256 repaidAssets, bytes calldata data) external;
}

interface IERC20Like {
    function safeTransferFrom(address from, address to, uint256 amount) external;
}

contract CallbackBeforeSettlementPositive {
    address public loanToken;

    function onMorphoRepay(uint256 repaidAssets, bytes calldata callbackData) external {
        (address liquidator, bytes memory data) = abi.decode(callbackData, (address, bytes));

        IPreLiquidationCallbackLike(liquidator).onPreLiquidate(repaidAssets, data);

        IERC20Like(loanToken).safeTransferFrom(liquidator, address(this), repaidAssets);
    }
}
