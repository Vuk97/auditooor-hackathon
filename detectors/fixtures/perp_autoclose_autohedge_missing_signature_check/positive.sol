pragma solidity ^0.8.20;

contract PerpAutoCloseMarket {
    struct SettlementParams {
        bytes swapData;
        uint256 minAmountOut;
        uint256 maxSlippageBps;
    }

    mapping(uint256 => address) public positionOwner;

    function autoClose(uint256 positionId, SettlementParams calldata settlementParams) external {
        address owner = positionOwner[positionId];
        require(owner != address(0), "missing position");

        _executeClose(positionId, settlementParams.swapData, settlementParams.minAmountOut, settlementParams.maxSlippageBps);
    }

    function _executeClose(
        uint256 positionId,
        bytes calldata swapData,
        uint256 minAmountOut,
        uint256 maxSlippageBps
    ) internal {
        positionId;
        swapData;
        minAmountOut;
        maxSlippageBps;
    }
}
