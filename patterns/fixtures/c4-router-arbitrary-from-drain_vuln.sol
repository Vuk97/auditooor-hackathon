// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}
library SafeERC20 {
    function safeTransferFrom(IERC20 t, address from, address to, uint256 amt) internal {
        require(t.transferFrom(from, to, amt));
    }
}

contract RouterVuln {
    using SafeERC20 for IERC20;

    // VULN: anyone can pass any `from` with an approval
    function pullToken(IERC20 token, address from, address to, uint256 amount) external {
        token.safeTransferFrom(from, to, amount);
    }
}
