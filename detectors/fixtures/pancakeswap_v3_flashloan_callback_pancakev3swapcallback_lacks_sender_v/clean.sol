// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20PancakeCallbackClean {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract PancakeV3CallbackSenderClean {
    address public immutable expectedPool;
    address public immutable token0;
    uint256 public lastPaid;
    address public lastPayer;

    constructor(address pool_, address token0_) {
        expectedPool = pool_;
        token0 = token0_;
    }

    function pancakeV3SwapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes calldata data
    ) external {
        require(msg.sender == expectedPool, "caller not pool");
        amount1Delta;
        address payer = abi.decode(data, (address));
        lastPayer = payer;

        if (amount0Delta > 0) {
            uint256 amountToPay = uint256(amount0Delta);
            lastPaid = amountToPay;
            IERC20PancakeCallbackClean(token0).transfer(expectedPool, amountToPay);
        }
    }
}
