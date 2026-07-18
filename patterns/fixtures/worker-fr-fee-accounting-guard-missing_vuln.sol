// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IWorkerFrToken {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address receiver, uint256 amount) external returns (bool);
}

interface IWorkerFrProtocolConfig {
    function protocolFeeConfig(address vault) external view returns (address receiver, uint256 share);
}

contract WorkerFrFeeAccountingGuardMissingVuln {
    uint112 public reserve0;
    uint112 public reserve1;
    uint256 public accruedFee;
    uint256 public totalSupply;
    address public token0;
    address public token1;
    mapping(address => uint256) public balanceOf;

    uint256 public feePerSecond;
    uint256 public lastFeeCollected;
    uint256 public accumulatedFees;

    address public feeReceiver;
    IWorkerFrProtocolConfig public protocolConfig;
    uint256 public constant CONFIG_SCALE = 1e4;
    uint256 public constant MAX_PROTOCOL_FEE_SHARE = 5000;

    function accrueFee() public {
        uint256 dt = block.timestamp - lastFeeCollected;
        accumulatedFees += feePerSecond * dt;
        lastFeeCollected = block.timestamp;
    }

    function burn(address to) external returns (uint256 amount0, uint256 amount1) {
        uint256 liquidity = balanceOf[address(this)];
        amount0 = (liquidity * reserve0) / totalSupply;
        amount1 = (liquidity * reserve1) / totalSupply;
        totalSupply -= liquidity;
        balanceOf[address(this)] = 0;
        IWorkerFrToken(token0).transfer(to, amount0);
        IWorkerFrToken(token1).transfer(to, amount1);
    }

    function swap(uint256 amount0Out, uint256 amount1Out, address to) external {
        uint256 bal0 = IWorkerFrToken(token0).balanceOf(address(this));
        uint256 bal1 = IWorkerFrToken(token1).balanceOf(address(this));
        require(bal0 * bal1 >= uint256(reserve0) * uint256(reserve1), "K");
        reserve0 = uint112(bal0 - amount0Out);
        reserve1 = uint112(bal1 - amount1Out);
        IWorkerFrToken(token0).transfer(to, amount0Out);
        IWorkerFrToken(token1).transfer(to, amount1Out);
    }

    function setFeePerSecond(uint256 newRate) external {
        feePerSecond = newRate;
    }

    function chargeFee(address, uint256 amount) external {
        accumulatedFees += amount;
    }

    function protocolFeeShare() public view returns (uint256) {
        (, uint256 protocolShare) = protocolConfig.protocolFeeConfig(address(this));
        return protocolShare;
    }
}
