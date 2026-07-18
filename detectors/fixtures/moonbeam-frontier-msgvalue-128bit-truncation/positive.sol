// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract FrontierMsgValueWrapperPositive {
    mapping(address => uint256) public wrappedBalance;
    uint256 public totalWrapped;
    uint256 public runtimeEscrowed;

    event Deposited(address indexed account, uint256 evmValue, uint128 runtimeValue);

    function depositToFrontierRuntime() external payable {
        // Models the vulnerable Frontier/Substrate boundary: the runtime leg
        // receives a u128 amount, while the EVM wrapper still sees full msg.value.
        uint128 runtimeValue = uint128(msg.value);

        runtimeEscrowed += uint256(runtimeValue);
        wrappedBalance[msg.sender] += msg.value;
        totalWrapped += msg.value;

        emit Deposited(msg.sender, msg.value, runtimeValue);
    }
}
