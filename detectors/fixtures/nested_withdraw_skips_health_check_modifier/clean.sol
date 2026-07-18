pragma solidity ^0.8.20;

interface IWiseLendingBareWithdrawClean {
    function withdrawExactShares(
        uint256 nftId,
        address token,
        uint256 shares
    ) external returns (uint256 withdrawnAssets);

    function healthStateCheck(uint256 nftId) external view returns (bool healthy);
}

contract NestedWithdrawSkipsHealthCheckModifierClean {
    IWiseLendingBareWithdrawClean public immutable wiseLending;
    address public immutable pendleChild;
    mapping(uint256 => uint256) public debtShares;

    constructor(IWiseLendingBareWithdrawClean lending, address collateralToken) {
        wiseLending = lending;
        pendleChild = collateralToken;
    }

    modifier syncPool(uint256 nftId) {
        require(nftId != 0, "bad nft");
        _;
    }

    function seedDebt(uint256 nftId, uint256 shares) external {
        debtShares[nftId] = shares;
    }

    function manualWithdraw(
        uint256 nftId,
        uint256 shares
    ) external syncPool(nftId) returns (uint256 withdrawnAssets) {
        require(debtShares[nftId] > 0, "only leveraged");
        withdrawnAssets = wiseLending.withdrawExactShares(nftId, pendleChild, shares);
        require(wiseLending.healthStateCheck(nftId), "unhealthy");
    }
}
