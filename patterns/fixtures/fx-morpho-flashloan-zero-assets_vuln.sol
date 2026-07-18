// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.0;

// Fixture: vulnerable flashLoan — no zero-amount guard.
// Source: morpho-org/morpho-blue@70e2636 (cantina-670)
// Vulnerability: flashLoan(token, 0, data) emits an event and triggers the callback with
// assets=0. The callback can be used for re-entrancy or to drain protocol state while
// bypassing the repayment check (safeTransferFrom of 0 always succeeds).

interface ICallback {
    function onMorphoFlashLoan(uint256 assets, bytes calldata data) external;
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract Fix {
    // VULNERABLE: assets == 0 is not rejected; callback still fires
    function flashLoan(address token, uint256 assets, bytes calldata data) external {
        // missing: require(assets != 0, "zero assets");

        IERC20(token).transfer(msg.sender, assets);
        ICallback(msg.sender).onMorphoFlashLoan(assets, data);
        IERC20(token).transferFrom(msg.sender, address(this), assets);
    }
}
