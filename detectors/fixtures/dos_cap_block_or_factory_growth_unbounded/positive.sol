// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPairFactory {
    function createPair(address tokenA, address tokenB) external returns (address pair);
}

contract BlockGasRefundPositive {
    mapping(address => uint256) public deposits;

    function relay(address target, bytes calldata data) external {
        (bool ok, ) = target.call(data);
        require(ok, "relay failed");

        uint256 gasRefund = block.gaslimit * tx.gasprice;
        deposits[msg.sender] -= gasRefund;
        (bool paid, ) = msg.sender.call{value: gasRefund}("");
        require(paid, "refund failed");
    }
}

contract FactoryGrowthPositive {
    IPairFactory public factory;
    address public weth;

    function launch(address token) external returns (address pair) {
        pair = factory.createPair(token, weth);
    }
}
