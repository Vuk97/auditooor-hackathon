// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 { function transfer(address,uint256) external returns (bool); }

/// CLEAN: callback validates both msg.sender and initiator.
contract FlashStrategyClean {
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
        require(initiator == address(this), "unauthorized initiator");
        (address target, uint256 amt) = abi.decode(params, (address, uint256));
        IERC20(token).transfer(target, amt);
        assets; amounts; premiums;
        return true;
    }
}
