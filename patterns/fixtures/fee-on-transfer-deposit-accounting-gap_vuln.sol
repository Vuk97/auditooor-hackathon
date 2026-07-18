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

// Vulnerable: deposit() calls safeTransferFrom and credits balances[user] +=
// amount without measuring actual received amount. Fee-on-transfer tokens
// cause over-credit → drain.
contract FoTDepositVuln {
    using SafeERC20 for IERC20;

    IERC20 public immutable token;
    mapping(address => uint256) public balances;
    uint256 public totalShares;

    constructor(address t) { token = IERC20(t); }

    // VULN: credits `amount` (argument) not delta of balanceOf(address(this)).
    function deposit(uint256 amount) external {
        token.safeTransferFrom(msg.sender, address(this), amount);
        balances[msg.sender] += amount;
    }

    // VULN variant: supply path, same shape, credits shares by passed amount.
    function supply(uint256 amount) external {
        token.safeTransferFrom(msg.sender, address(this), amount);
        totalShares += amount;
        balances[msg.sender] += amount;
    }
}
