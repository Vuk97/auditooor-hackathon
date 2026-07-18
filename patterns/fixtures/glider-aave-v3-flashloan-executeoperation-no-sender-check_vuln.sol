// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 { function transfer(address, uint256) external returns (bool); }

contract AaveReceiverVuln {
    address public immutable POOL;
    constructor(address pool) { POOL = pool; }

    // VULN: callback lacks caller authentication -- pool address and initiator not validated
    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata,
        address,
        bytes calldata
    ) external returns (bool) {
        IERC20(assets[0]).transfer(msg.sender, amounts[0]);
        return true;
    }
}
