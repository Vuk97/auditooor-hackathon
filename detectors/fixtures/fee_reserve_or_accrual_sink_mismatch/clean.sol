// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

interface IProtocolConfigLike {
    function protocolFeeConfig(address vault) external view returns (address receiver, uint256 share);
}

contract FeeReserveMismatchClean {
    uint112 public reserve0;
    uint112 public reserve1;
    uint256 public accruedFee;
    uint256 public totalSupply;
    address public token0;
    address public token1;
    mapping(address => uint256) public balanceOf;

    function burn(address to) external returns (uint256 amount0, uint256 amount1) {
        uint256 liquidity = balanceOf[address(this)];
        uint256 realReserve0 = reserve0 - accruedFee;
        amount0 = (liquidity * realReserve0) / totalSupply;
        amount1 = (liquidity * uint256(reserve1)) / totalSupply;
        balanceOf[address(this)] = 0;
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
}

contract FeeAccrualMismatchClean {
    uint256 public feePerSecond;
    uint256 public lastFeeCollected;
    uint256 public accumulatedFees;

    function accrueFee() public {
        uint256 dt = block.timestamp - lastFeeCollected;
        accumulatedFees += feePerSecond * dt;
        lastFeeCollected = block.timestamp;
    }

    function setFeePerSecond(uint256 newRate) external {
        accrueFee();
        feePerSecond = newRate;
    }

    function chargeFee(uint256 amount) external {
        accrueFee();
        accumulatedFees += amount;
    }
}

contract FeeShareMismatchClean {
    address public feeReceiver;
    IProtocolConfigLike public protocolConfig;
    uint256 public constant CONFIG_SCALE = 1e4;
    uint256 public constant MAX_PROTOCOL_FEE_SHARE = 5000;

    function protocolFeeShare() public view returns (uint256) {
        if (feeReceiver == address(0)) return CONFIG_SCALE;

        (, uint256 protocolShare) = protocolConfig.protocolFeeConfig(address(this));
        if (protocolShare > MAX_PROTOCOL_FEE_SHARE) return MAX_PROTOCOL_FEE_SHARE;

        return protocolShare;
    }
}

contract ProtocolFeeSinkMismatchClean {
    address public token;
    IProtocolConfigLike public protocolConfig;
    uint256 public constant CONFIG_SCALE = 1e4;
    uint256 public constant MAX_PROTOCOL_FEE_SHARE = 5000;
    uint256 public feesAccrued;

    function convertFees() external {
        (address protocolReceiver, uint256 protocolShare) =
            protocolConfig.protocolFeeConfig(address(this));
        if (protocolReceiver == address(0)) return;
        if (protocolShare > MAX_PROTOCOL_FEE_SHARE) {
            protocolShare = MAX_PROTOCOL_FEE_SHARE;
        }

        uint256 protocolAmount = (feesAccrued * protocolShare) / CONFIG_SCALE;
        feesAccrued = 0;
        IERC20Like(token).transfer(protocolReceiver, protocolAmount);
    }

    function sweepUserDust(address to, uint256 amount) external {
        IERC20Like(token).transfer(to, amount);
    }
}
