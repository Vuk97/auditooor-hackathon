pragma solidity ^0.8.0;

contract VaultPreviewClean {
    uint256 public totalSupply = 1e18;
    uint256 public totalAssets = 1e18 + 1;

    // previewDeposit uses correct floor rounding
    function previewDeposit(uint256 assets) external view returns (uint256) {
        return (assets * totalSupply) / totalAssets;
    }

    function previewMint(uint256 shares) external view returns (uint256) {
        return mulDivUp(shares, totalAssets, totalSupply);
    }

    function previewWithdraw(uint256 assets) external view returns (uint256) {
        return mulDivUp(assets, totalSupply, totalAssets);
    }

    // previewRedeem uses correct floor rounding
    function previewRedeem(uint256 shares) external view returns (uint256) {
        return (shares * totalAssets) / totalSupply;
    }

    function mulDivUp(uint256 a, uint256 b, uint256 d) internal pure returns (uint256) {
        return (a * b + d - 1) / d;
    }
}