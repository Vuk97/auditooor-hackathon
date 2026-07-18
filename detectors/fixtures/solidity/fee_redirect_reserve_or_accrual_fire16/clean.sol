// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

interface IProtocolConfig {
    function protocolFeeConfig(address vault) external view returns (address receiver, uint256 share);
}

contract FeeRedirectReserveOrAccrualClean {
    uint112 public reserve0;
    uint112 public reserve1;
    uint256 public accruedFee;
    uint256 public totalSupply;
    uint256 public feePerSecond;
    uint256 public lastFeeCollected;
    uint256 public accumulatedFees;
    address public token0;
    address public token1;
    address public protocolReceiver;
    IProtocolConfig public protocolConfig;
    uint256 public constant MAX_PROTOCOL_FEE_SHARE = 5000;

    mapping(address => uint256) public balanceOf;

    function accrueFee() public {
        uint256 dt = block.timestamp - lastFeeCollected;
        accumulatedFees += feePerSecond * dt;
        lastFeeCollected = block.timestamp;
    }

    function burn(address to) external returns (uint256 amount0, uint256 amount1) {
        uint256 liquidity = balanceOf[address(this)];
        uint256 realReserve0 = reserve0 - accruedFee;
        amount0 = (liquidity * realReserve0) / totalSupply;
        amount1 = (liquidity * reserve1) / totalSupply;
        IERC20Like(token0).transfer(to, amount0);
        IERC20Like(token1).transfer(to, amount1);
    }

    function swap(uint256 amount0Out, uint256 amount1Out, address to) external {
        uint256 bal0 = IERC20Like(token0).balanceOf(address(this)) - accruedFee;
        uint256 bal1 = IERC20Like(token1).balanceOf(address(this));
        require(bal0 * bal1 >= uint256(reserve0 - accruedFee) * uint256(reserve1), "K");
        reserve0 = uint112(bal0 + accruedFee - amount0Out);
        reserve1 = uint112(bal1 - amount1Out);
        IERC20Like(token0).transfer(to, amount0Out);
        IERC20Like(token1).transfer(to, amount1Out);
    }

    function setFeePerSecond(uint256 newRate) external {
        accrueFee();
        feePerSecond = newRate;
    }

    function chargeFee(uint256 amount) external {
        accrueFee();
        accumulatedFees += amount;
    }

    function protocolFeeShare() public view returns (uint256) {
        if (protocolReceiver == address(0)) {
            return 1e4;
        }
        (, uint256 protocolShare) = protocolConfig.protocolFeeConfig(address(this));
        if (protocolShare > MAX_PROTOCOL_FEE_SHARE) {
            return MAX_PROTOCOL_FEE_SHARE;
        }
        return protocolShare;
    }

    function convertFees(address token, uint256 totalFees) external {
        if (protocolReceiver == address(0)) {
            return;
        }
        (, uint256 protocolShare) = protocolConfig.protocolFeeConfig(address(this));
        if (protocolShare > MAX_PROTOCOL_FEE_SHARE) {
            protocolShare = MAX_PROTOCOL_FEE_SHARE;
        }
        uint256 protocolAmount = (totalFees * protocolShare) / 1e4;
        IERC20Like(token).transfer(protocolReceiver, protocolAmount);
    }
}
