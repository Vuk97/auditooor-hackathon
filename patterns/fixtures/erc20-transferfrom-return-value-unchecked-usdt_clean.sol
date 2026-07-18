// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

/// @notice CLEAN FIXTURE — detector MUST NOT fire.
///
/// Same functional shape as the vuln fixture, but every ERC20 interaction
/// is wrapped in OpenZeppelin's SafeERC20. The negative-regex guard
/// (`safeTransferFrom|safeTransfer\(|SafeERC20|IERC20Permit|_safeTransfer`)
/// suppresses the match.
library SafeERC20 {
    function safeTransfer(IERC20 t, address to, uint256 amt) internal {
        bool ok = t.transfer(to, amt);
        require(ok, "SafeERC20: transfer failed");
    }
    function safeTransferFrom(IERC20 t, address from, address to, uint256 amt) internal {
        bool ok = t.transferFrom(from, to, amt);
        require(ok, "SafeERC20: transferFrom failed");
    }
}

contract UsdtSafeClean {
    using SafeERC20 for IERC20;

    IERC20 public immutable token;
    mapping(address => uint256) public balances;

    constructor(address t) { token = IERC20(t); }

    // Safe: uses SafeERC20.safeTransferFrom — negative guard matches
    // `safeTransferFrom` and `SafeERC20`, detector suppressed.
    function deposit(uint256 amt) external {
        token.safeTransferFrom(msg.sender, address(this), amt);
        balances[msg.sender] += amt;
    }

    // Safe: uses SafeERC20.safeTransfer.
    function withdraw(uint256 amt) external {
        balances[msg.sender] -= amt;
        token.safeTransfer(msg.sender, amt);
    }
}
