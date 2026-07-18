// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20StateCheckBoundaryClean {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

struct PackedUserOperationStateCheckClean {
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

contract StateCheckBeforeTokenMutationPoolClean {
    IERC20StateCheckBoundaryClean public token0;
    IERC20StateCheckBoundaryClean public token1;
    uint112 public reserve0;
    uint112 public reserve1;

    constructor(address _token0, address _token1) {
        token0 = IERC20StateCheckBoundaryClean(_token0);
        token1 = IERC20StateCheckBoundaryClean(_token1);
    }

    function swap(uint256 amount0Out, uint256 amount1Out, address to) external {
        require(amount0Out > 0 || amount1Out > 0, "no output");

        if (amount0Out > 0) {
            token0.transfer(to, amount0Out);
        }
        if (amount1Out > 0) {
            token1.transfer(to, amount1Out);
        }

        uint256 balance0 = token0.balanceOf(address(this));
        uint256 balance1 = token1.balanceOf(address(this));
        uint256 amount0In = balance0 > reserve0 - amount0Out ? balance0 - (reserve0 - amount0Out) : 0;
        uint256 amount1In = balance1 > reserve1 - amount1Out ? balance1 - (reserve1 - amount1Out) : 0;
        require(amount0In > 0 || amount1In > 0, "no input");

        reserve0 = uint112(balance0);
        reserve1 = uint112(balance1);
    }
}

contract StateCheckBeforeSenderMutationPaymasterClean {
    address public immutable entryPoint;
    mapping(address => bool) public allowedSenders;
    bytes32 internal constant SIG_VALIDATION_SUCCESS = bytes32(0);

    constructor(address _entryPoint) {
        entryPoint = _entryPoint;
    }

    modifier onlyEntryPoint() {
        require(msg.sender == entryPoint, "only EntryPoint");
        _;
    }

    function setAllowedSender(address account, bool ok) external {
        allowedSenders[account] = ok;
    }

    function validatePaymasterUserOp(
        PackedUserOperationStateCheckClean calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external onlyEntryPoint returns (bytes memory context, uint256 validationData) {
        (userOpHash, maxCost);
        require(allowedSenders[userOp.sender], "sender not sponsored");
        return ("", uint256(SIG_VALIDATION_SUCCESS));
    }
}
