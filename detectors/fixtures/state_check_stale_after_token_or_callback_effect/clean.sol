// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20StaleEffectClean {
    function balanceOf(address account) external view returns (uint256);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

interface IPaymasterPolicyEffectClean {
    function beforeSponsor(address sender, uint256 maxCost) external;
}

struct PackedUserOperationStaleEffectClean {
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

contract TokenEffectFreshDeltaClean {
    IERC20StaleEffectClean public token0;
    IERC20StaleEffectClean public token1;
    uint112 public reserve0;
    uint112 public reserve1;

    constructor(address _token0, address _token1) {
        token0 = IERC20StaleEffectClean(_token0);
        token1 = IERC20StaleEffectClean(_token1);
    }

    function swap(uint256 amount0In, address to) external {
        require(amount0In > 0 && reserve0 > 0 && reserve1 > 0, "bad input");

        uint256 balanceBefore = token0.balanceOf(address(this));
        token0.transferFrom(msg.sender, address(this), amount0In);
        uint256 balanceAfter = token0.balanceOf(address(this));
        uint256 actualReceived = balanceAfter - balanceBefore;
        require(actualReceived > 0, "no credit");

        uint256 amount1Out = actualReceived * uint256(reserve1) / (uint256(reserve0) + actualReceived);
        token1.transfer(to, amount1Out);

        uint256 newBal1 = token1.balanceOf(address(this));
        reserve0 = uint112(balanceAfter);
        reserve1 = uint112(newBal1);
    }
}

contract CallbackEffectRevalidatedPolicyClean {
    IPaymasterPolicyEffectClean public policy;
    mapping(address => bool) public sponsored;
    mapping(address => uint256) public quota;
    mapping(address => uint256) public spent;
    bytes32 internal constant SIG_VALIDATION_SUCCESS = bytes32(0);

    constructor(address _policy) {
        policy = IPaymasterPolicyEffectClean(_policy);
    }

    function validatePaymasterUserOp(
        PackedUserOperationStaleEffectClean calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external returns (bytes memory context, uint256 validationData) {
        require(sponsored[userOp.sender] && quota[userOp.sender] >= maxCost, "not sponsored");

        policy.beforeSponsor(userOp.sender, maxCost);

        uint256 quotaAfter = quota[userOp.sender];
        require(sponsored[userOp.sender] && quotaAfter >= maxCost, "not sponsored after policy");
        spent[userOp.sender] += maxCost;
        userOpHash;
        return ("", uint256(SIG_VALIDATION_SUCCESS));
    }
}
