// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.0;

// Fixture: fixed flashLoan — zero-assets guard added.
// Source: morpho-org/morpho-blue@70e2636 (cantina-670)

interface ICallback {
    function onMorphoFlashLoan(uint256 assets, bytes calldata data) external;
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract Fix {
    string internal constant ZERO_ASSETS = "zero assets";

    // FIXED: reject zero-amount flash loans
    function flashLoan(address token, uint256 assets, bytes calldata data) external {
        require(assets != 0, ZERO_ASSETS);

        IERC20(token).transfer(msg.sender, assets);
        ICallback(msg.sender).onMorphoFlashLoan(assets, data);
        IERC20(token).transferFrom(msg.sender, address(this), assets);
    }
}
