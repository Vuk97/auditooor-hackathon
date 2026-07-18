// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICurvePoolC {
    function swap(uint256 amountIn, uint256 minOut) external returns (uint256);
}

interface IOracle {
    function priceOf(address token) external view returns (uint256);
}

contract HarvesterClean {
    address public dedicatedMsgSender; // Gelato dedicated proxy per EOA
    address public pool;
    address public oracle;
    uint256 public maxSlippageBps = 100; // 1%

    constructor(address _dedicated, address _pool, address _oracle) {
        dedicatedMsgSender = _dedicated;
        pool = _pool;
        oracle = _oracle;
    }

    // FIXED: caller must equal protocol-owned dedicated msg-sender, and
    // minimumAmountOut is computed inline from an oracle rather than
    // taken as user input.
    function harvest(address yieldToken) external returns (uint256 out) {
        require(msg.sender == dedicatedMsgSender, "not dedicated");
        uint256 expected = IOracle(oracle).priceOf(yieldToken); // 1e18 scaled per 1e18 in
        uint256 minOut = (expected * (10000 - maxSlippageBps)) / 10000;
        out = ICurvePoolC(pool).swap(1e18, minOut);
    }
}
