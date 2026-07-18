// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC1155FeeToken {
    function balanceOf(address account, uint256 id) external view returns (uint256);
    function safeTransferFrom(
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes calldata data
    ) external;
}

contract MatchOrdersFeeReentrancyPositive {
    IERC1155FeeToken public immutable conditionalTokens;
    address public feeReceiver;
    uint256 public batchedExchangeFees;
    uint256 public lastFeeBalance;
    mapping(bytes32 => uint256) public orderStatus;

    constructor(IERC1155FeeToken tokens, address receiver) {
        conditionalTokens = tokens;
        feeReceiver = receiver;
    }

    function matchOrders(
        bytes32 orderHash,
        uint256 feeAssetId,
        uint256 feeAmount
    ) external {
        uint256 balanceBefore = conditionalTokens.balanceOf(address(this), feeAssetId);

        conditionalTokens.safeTransferFrom(
            address(this),
            feeReceiver,
            feeAssetId,
            feeAmount,
            ""
        );

        batchedExchangeFees =
            conditionalTokens.balanceOf(address(this), feeAssetId) -
            balanceBefore;
        orderStatus[orderHash] = 1;
        lastFeeBalance = batchedExchangeFees;
    }
}
