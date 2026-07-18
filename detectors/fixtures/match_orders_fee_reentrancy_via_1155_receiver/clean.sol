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

contract MatchOrdersFeeReentrancyClean {
    IERC1155FeeToken public immutable conditionalTokens;
    address public feeReceiver;
    uint256 public batchedExchangeFees;
    uint256 public lastFeeBalance;
    mapping(bytes32 => uint256) public orderStatus;
    uint256 private _status;

    modifier nonReentrant() {
        require(_status != 2, "reentrant");
        _status = 2;
        _;
        _status = 1;
    }

    constructor(IERC1155FeeToken tokens, address receiver) {
        conditionalTokens = tokens;
        feeReceiver = receiver;
        _status = 1;
    }

    function matchOrders(
        bytes32 orderHash,
        uint256 feeAssetId,
        uint256 feeAmount
    ) external nonReentrant {
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
