// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract UncheckedErc20ReturnPositive {
    address public immutable token;

    constructor(address _token) {
        token = _token;
    }

    function sweep(address to, uint256 amount) external {
        IERC20(token).transfer(to, amount);
    }
}
