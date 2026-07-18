// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 { function transfer(address,uint256) external returns (bool); }

contract FlashStrategyVuln {
    address public pool;
    address public token;
    constructor(address p, address t) { pool = p; token = t; }

    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address initiator,
        bytes calldata params
    ) external returns (bool) {
        require(msg.sender == pool, "not pool");
        (address target, uint256 amt) = abi.decode(params, (address, uint256));
        IERC20(token).transfer(target, amt);
        initiator; assets; amounts; premiums;
        return true;
    }
}
