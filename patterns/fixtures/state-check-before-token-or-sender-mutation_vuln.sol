// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20StateCheckBoundary {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

struct PackedUserOperationStateCheck {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees;
    bytes paymasterAndData;
    bytes signature;
}

contract StateCheckBeforeTokenMutationPoolVuln {
    IERC20StateCheckBoundary public token0;
    IERC20StateCheckBoundary public token1;
    uint112 public reserve0;
    uint112 public reserve1;

    constructor(address _token0, address _token1) {
        token0 = IERC20StateCheckBoundary(_token0);
        token1 = IERC20StateCheckBoundary(_token1);
    }

    function swap(uint256 amount0In, uint256 amount1Out, address to) external {
        require(amount1Out > 0, "no output");

        uint256 quotedOut = amount0In * uint256(reserve1) / uint256(reserve0);
        token1.transfer(to, amount1Out);

        uint256 newBal0 = token0.balanceOf(address(this));
        uint256 newBal1 = token1.balanceOf(address(this));
        require(newBal0 * newBal1 >= uint256(reserve0) * uint256(reserve1), "K");

        reserve0 = uint112(newBal0);
        reserve1 = uint112(newBal1);
        quotedOut;
    }
}

contract StateCheckBeforeSenderMutationPaymasterVuln {
    address public immutable entryPoint;
    bytes32 internal constant SIG_VALIDATION_SUCCESS = bytes32(0);

    constructor(address _entryPoint) {
        entryPoint = _entryPoint;
    }

    modifier onlyEntryPoint() {
        require(msg.sender == entryPoint, "only EntryPoint");
        _;
    }

    function validatePaymasterUserOp(
        PackedUserOperationStateCheck calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external onlyEntryPoint returns (bytes memory context, uint256 validationData) {
        (userOp, userOpHash, maxCost);
        return ("", uint256(SIG_VALIDATION_SUCCESS));
    }
}
