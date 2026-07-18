// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 { function transfer(address,uint256) external returns (bool); }

contract OdosReceiverClean {
    function swap(address token, address receiver, uint256 amt) external {
        require(receiver != address(0), "zero receiver");
        IERC20(token).transfer(receiver, amt);
    }
}
