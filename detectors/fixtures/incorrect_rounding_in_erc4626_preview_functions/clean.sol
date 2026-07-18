pragma solidity ^0.8.20;

library Math {
    enum Rounding {
        Floor,
        Ceil
    }
}

abstract contract ERC4626 {
    function totalAssets() public view virtual returns (uint256);
}

contract IncorrectRoundingInErc4626PreviewFunctionsClean is ERC4626 {
    function totalAssets() public pure override returns (uint256) {
        return 1_000_000;
    }

    function previewRedeem(uint256 shares) public view returns (uint256) {
        return _convertToAssets(shares, Math.Rounding.Floor);
    }

    function _convertToAssets(uint256 shares, Math.Rounding rounding) internal pure returns (uint256) {
        if (rounding == Math.Rounding.Ceil) {
            return shares + 1;
        }
        return shares;
    }
}
