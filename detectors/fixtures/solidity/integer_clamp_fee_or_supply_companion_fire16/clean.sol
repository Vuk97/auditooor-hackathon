// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

library FullMath {
    function mulDiv(uint256 a, uint256 b, uint256 denominator) internal pure returns (uint256) {
        return a * b / denominator;
    }
}

contract Fire16IntegerClampFeeOrSupplyClean {
    uint256 public constant PIPS_DENOMINATOR = 1_000_000;
    uint256 public constant MAX_BUY = type(uint128).max;
    uint256 public unitPrice = 3e18;
    uint256 public emissionMultiplier = 2e18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    function computeSwapProtocolFee(
        uint256 amountIn,
        uint256 feeAmount,
        uint256 protocolFee,
        uint256 lpFee
    ) internal pure returns (uint256) {
        uint256 swapFee = protocolFee + lpFee;
        if (swapFee == protocolFee) {
            return feeAmount;
        }
        return (amountIn + feeAmount) * protocolFee / PIPS_DENOMINATOR;
    }

    function buy(uint256 requestedTokens) external returns (uint256 cost) {
        require(requestedTokens <= MAX_BUY, "max buy");
        cost = FullMath.mulDiv(requestedTokens, unitPrice, 1e18);
        _mint(msg.sender, requestedTokens);
    }

    function enter(uint256 quantity) external returns (uint256 minted) {
        require(quantity <= MAX_BUY, "max quantity");
        minted = FullMath.mulDiv(quantity, emissionMultiplier, 1e18);
        balanceOf[msg.sender] += minted;
        totalSupply += minted;
    }

    function _mint(address to, uint256 amount) internal {
        balanceOf[to] += amount;
        totalSupply += amount;
    }
}
