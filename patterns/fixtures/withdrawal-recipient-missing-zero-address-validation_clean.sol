// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract MockCollateralToken {
    address public immutable VAULT;

    error InvalidRecipient();

    constructor(address vault) {
        VAULT = vault;
    }

    function unwrap(address asset, address to, uint256 amount) external {
        if (to == address(0)) revert InvalidRecipient();
        IERC20(asset).transferFrom(VAULT, to, amount);
    }
}
