// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract FrontierMsgValueWrapperClean {
    mapping(address => uint256) public wrappedBalance;
    uint256 public totalWrapped;
    uint256 public runtimeEscrowed;

    event Deposited(address indexed account, uint256 evmValue, uint128 runtimeValue);

    function depositToFrontierRuntime() external payable {
        require(msg.value <= type(uint128).max, "frontier value overflow");

        uint128 runtimeValue = uint128(msg.value);
        runtimeEscrowed += uint256(runtimeValue);
        wrappedBalance[msg.sender] += msg.value;
        totalWrapped += msg.value;

        emit Deposited(msg.sender, msg.value, runtimeValue);
    }
}
