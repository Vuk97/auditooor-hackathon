// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Minimal {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract WithdrawClaimRecipientIgnoredHardcodedSinkPositive {
    IERC20Minimal public immutable asset;

    mapping(address => uint256) public shares;

    constructor(IERC20Minimal _asset) {
        asset = _asset;
    }

    function withdraw(address recipient, uint256 shareAmount) external returns (uint256 assets) {
        require(recipient != address(0), "bad recipient");
        require(shares[msg.sender] >= shareAmount, "insufficient shares");

        shares[msg.sender] -= shareAmount;
        assets = _previewWithdraw(shareAmount);

        asset.transfer(msg.sender, assets);
    }

    function _previewWithdraw(uint256 shareAmount) internal pure returns (uint256) {
        return shareAmount * 2;
    }
}
