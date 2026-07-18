// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPairFactoryClean {
    function createPair(address tokenA, address tokenB) external returns (address pair);
    function getPair(address tokenA, address tokenB) external view returns (address pair);
}

contract BlockGasRefundClean {
    uint256 private constant FIXED_OVERHEAD = 21000;
    uint256 private constant MAX_REFUND_GAS = 300000;
    mapping(address => uint256) public deposits;

    function relay(address target, bytes calldata data, uint256 startGas) external {
        (bool ok, ) = target.call(data);
        require(ok, "relay failed");

        uint256 used = startGas - gasleft() + FIXED_OVERHEAD;
        if (used > MAX_REFUND_GAS) {
            used = MAX_REFUND_GAS;
        }
        uint256 owed = used * tx.gasprice;
        deposits[msg.sender] -= owed;
        (bool paid, ) = msg.sender.call{value: owed}("");
        require(paid, "refund failed");
    }
}

contract FactoryGrowthClean {
    IPairFactoryClean public factory;
    address public weth;

    function launch(address token) external returns (address pair) {
        pair = factory.getPair(token, weth);
        if (pair == address(0)) {
            pair = factory.createPair(token, weth);
        }
    }
}
