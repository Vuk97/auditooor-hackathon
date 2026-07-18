pragma solidity ^0.8.20;

library SignatureChecker {
    function isValidSignatureNow(address, bytes32, bytes memory) internal pure returns (bool) {
        return true;
    }
}

contract PerpAutoCloseMarket {
    using SignatureChecker for address;

    struct SettlementParams {
        bytes swapData;
        uint256 minAmountOut;
        uint256 maxSlippageBps;
    }

    mapping(uint256 => address) public positionOwner;

    function autoClose(
        uint256 positionId,
        SettlementParams calldata settlementParams,
        bytes calldata ownerSignature
    ) external {
        address owner = positionOwner[positionId];
        require(owner != address(0), "missing position");

        bytes32 digest = keccak256(
            abi.encode(
                positionId,
                keccak256(settlementParams.swapData),
                settlementParams.minAmountOut,
                settlementParams.maxSlippageBps
            )
        );
        require(owner.isValidSignatureNow(digest, ownerSignature), "invalid owner signature");

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
