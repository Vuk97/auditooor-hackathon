pragma solidity ^0.8.20;

contract OptionsUncappedPositionCountMakesAccountUnliquidatablePositive {
    mapping(address => uint256[]) internal positionIdList;
    mapping(uint256 => uint256) internal positionSize;

    event Liquidated(address indexed account, uint256 shortfall);

    function mintOptions(uint256 tokenId, uint256 size) external {
        require(size > 0, "zero size");
        positionIdList[msg.sender].push(tokenId);
        positionSize[tokenId] = size;
    }

    function liquidateAccount(address account) external returns (uint256 collateralShortfall) {
        uint256[] storage positions = positionIdList[account];
        for (uint256 i = 0; i < positions.length; ++i) {
            collateralShortfall += _premiumOwed(positions[i]);
        }

        if (collateralShortfall > 0) {
            _settleBankruptcy(account, collateralShortfall);
        }
    }

    function _premiumOwed(uint256 tokenId) internal view returns (uint256) {
        return positionSize[tokenId] + _oraclePremium(tokenId);
    }

    function _oraclePremium(uint256 tokenId) internal pure returns (uint256) {
        return tokenId % 7;
    }

    function _settleBankruptcy(address account, uint256 shortfall) internal {
        emit Liquidated(account, shortfall);
    }
}
