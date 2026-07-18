// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IReceiptLike {
    function ownerOf(uint256 tokenId) external view returns (address);
}

contract ReceiptDataReader {
    struct ReceiptInfo {
        uint256 tokenId;
        address owner;
        address underlying;
        uint8 decimals;
        address vault;
    }

    IReceiptLike public receiptToken;
    address public underlyingAsset;
    address public vault;
    uint8 public receiptDecimals;

    constructor(IReceiptLike receiptToken_) {
        receiptToken = receiptToken_;
        underlyingAsset = address(0xA11CE);
        vault = address(0xB0B);
        receiptDecimals = 18;
    }

    function getReceiptData(uint256 receiptId) external view returns (ReceiptInfo memory) {
        ReceiptInfo memory info = ReceiptInfo({
            tokenId: receiptId,
            owner: receiptToken.ownerOf(receiptId),
            underlying: underlyingAsset,
            decimals: receiptDecimals,
            vault: vault
        });
        return info;
    }
}
