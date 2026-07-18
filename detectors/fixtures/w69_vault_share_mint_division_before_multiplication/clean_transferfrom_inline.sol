// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20LikeInline {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

library MathInline {
    function mulDiv(uint256 x, uint256 y, uint256 z) internal pure returns (uint256) {
        return (x * y) / z;
    }
}

contract W69VaultShareMintDivisionBeforeMultiplicationCleanTransferFromInline {
    IERC20LikeInline public immutable asset;
    uint256 public totalShareSupply = 1_000_000e18;
    uint256 public managedAssets = 10_000_000e18;
    mapping(address => uint256) public balanceOf;

    constructor(IERC20LikeInline asset_) {
        asset = asset_;
    }

    function totalAssets() public view returns (uint256) {
        return managedAssets;
    }

    function totalSupply() public view returns (uint256) {
        return totalShareSupply;
    }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = MathInline.mulDiv(assets, totalSupply(), totalAssets());
        require(shares > 0, "zero shares");
        asset.transferFrom(msg.sender, address(this), assets);
        balanceOf[receiver] += shares;
        totalShareSupply += shares;
    }
}
