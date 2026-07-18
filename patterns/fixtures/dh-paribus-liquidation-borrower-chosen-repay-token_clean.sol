// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ParibusLiqClean {
    mapping(address => mapping(address => uint256)) public borrowBalance;
    mapping(address => mapping(address => uint256)) public repaid;
    function liquidateBorrow(address victim, address repayAsset, uint256 amt, address collateralAsset) external {
        require(borrowBalance[victim][repayAsset] > 0, "not borrowed");
        repaid[victim][repayAsset] += amt;
        _seize(victim, msg.sender, collateralAsset, amt * 11 / 10);
    }
    function _seize(address, address, address, uint256) internal {}
}
