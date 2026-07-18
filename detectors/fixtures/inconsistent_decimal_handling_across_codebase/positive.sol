// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Metadata {
    function decimals() external view returns (uint8);
}

contract InconsistentDecimalHandlingAcrossCodebasePositive {
    address public RBT;

    constructor(address rbt_) {
        RBT = rbt_;
    }

    function payoutFor(uint256 usdmAmount, uint256 rbtPrice) public view returns (uint256 payout) {
        payout = (usdmAmount * 1e18) / rbtPrice;
        require(
            payout >= 10 ** IERC20Metadata(address(RBT)).decimals() / 100,
            "Bond too small"
        );
    }

    function valueOfToken(address _token, uint256 _amount) public view returns (uint256 value_) {
        value_ = (_amount * 10 ** IERC20Metadata(address(RBT)).decimals())
            / 10 ** IERC20Metadata(_token).decimals();
    }
}
