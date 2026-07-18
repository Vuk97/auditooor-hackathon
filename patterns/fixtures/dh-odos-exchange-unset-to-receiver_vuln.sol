// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 { function transfer(address,uint256) external returns (bool); }

contract OdosReceiverVuln {
    function swap(address token, address receiver, uint256 amt) external {
        IERC20(token).transfer(receiver, amt);
    }
}
