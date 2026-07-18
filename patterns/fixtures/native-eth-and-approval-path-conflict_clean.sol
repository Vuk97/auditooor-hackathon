// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire. Same deposit surface as
/// the vuln fixture, but the native and ERC20 payment paths are mutually
/// exclusive via a `require(msg.value == 0)` guard on the approval branch
/// (and implicit XOR by early-returning from the native branch).

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IWETH {
    function deposit() external payable;
}

contract NativeApprovalClean {
    address public immutable weth;
    mapping(address => uint256) public balances;

    constructor(address _weth) {
        weth = _weth;
    }

    function deposit(uint256 amount) external payable {
        if (msg.value > 0) {
            // Native path: the ERC20 path is forbidden in this branch.
            require(amount == 0, "native-only");
            IWETH(weth).deposit{value: msg.value}();
            balances[msg.sender] += msg.value;
            return;
        }

        // Approval path: native path is forbidden in this branch.
        require(msg.value == 0, "approval-only");
        IERC20(weth).transferFrom(msg.sender, address(this), amount);
        balances[msg.sender] += amount;
    }
}
