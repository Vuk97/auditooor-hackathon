// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IERC20Clean { function transferFrom(address from, address to, uint256 amt) external returns (bool); }

contract DrainClean {
    IERC20Clean public token;

    function pull(address from, uint256 amount) external {
        require(msg.sender == from, "only owner of from");
        token.transferFrom(from, address(this), amount);
    }
}
