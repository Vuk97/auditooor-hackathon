// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

library SafeERC20 {
    function safeTransferFrom(IERC20 t, address f, address to, uint256 a) internal {
        require(t.transferFrom(f, to, a), "stf");
    }
}

// Clean: pre/post balanceOf(address(this)) snapshot measures the actual
// received amount, so fee-on-transfer tokens can't over-credit the caller.
contract FoTDepositClean {
    using SafeERC20 for IERC20;

    IERC20 public immutable token;
    mapping(address => uint256) public balances;
    uint256 public totalShares;

    constructor(address t) { token = IERC20(t); }

    // CLEAN: credits `balanceAfter - balanceBefore` delta, not the argument.
    function deposit(uint256 amount) external {
        uint256 snapshotBalanceBefore = token.balanceOf(address(this));
        token.safeTransferFrom(msg.sender, address(this), amount);
        uint256 balanceAfter = token.balanceOf(address(this));
        uint256 received = balanceAfter - snapshotBalanceBefore;
        balances[msg.sender] += received;
    }

    // CLEAN: same delta pattern on supply().
    function supply(uint256 amount) external {
        uint256 balanceBefore = token.balanceOf(address(this));
        token.safeTransferFrom(msg.sender, address(this), amount);
        uint256 _received = token.balanceOf(address(this)) - balanceBefore;
        totalShares += _received;
        balances[msg.sender] += _received;
    }
}
