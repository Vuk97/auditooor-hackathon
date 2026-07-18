// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BebopNonceBookClean {
    mapping(address => uint256) public nonceBitmap;

    event AggregateOrderInvalidated(address indexed maker, uint256 nonce);

    function assertAndInvalidateAggregateOrder(address maker, uint256 nonce) external {
        require(msg.sender == maker, "maker only");
        uint256 bit = 1 << (nonce & 255);
        nonceBitmap[maker] |= bit;
        emit AggregateOrderInvalidated(maker, nonce);
    }

    function fillAggregateOrder(address maker, uint256 nonce) external view returns (bool) {
        uint256 bit = 1 << (nonce & 255);
        return nonceBitmap[maker] & bit == 0;
    }
}
