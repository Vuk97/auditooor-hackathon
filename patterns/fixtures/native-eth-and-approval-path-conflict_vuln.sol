// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// native-eth-and-approval-path-conflict detector. DO NOT DEPLOY.
///
/// `deposit` is payable AND pulls pre-approved WETH via transferFrom in the
/// same body, without gating the two payment paths. A caller who both
/// approves `amount` WETH and sends `{value: amount}` is double-credited.

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IWETH {
    function deposit() external payable;
}

contract NativeApprovalVuln {
    address public immutable weth;
    mapping(address => uint256) public balances;

    constructor(address _weth) {
        weth = _weth;
    }

    /// Intended: user sends ETH OR pre-approves WETH, never both.
    /// Actually: both paths execute — balance credited `amount`, but
    /// contract holds 2*amount of WETH.
    function deposit(uint256 amount) external payable {
        // Native path: wrap incoming msg.value into WETH.
        IWETH(weth).deposit{value: msg.value}();

        // Approval path: also pull pre-approved WETH from caller.
        IERC20(weth).transferFrom(msg.sender, address(this), amount);

        // Only credited once — contract now holds `amount` more WETH than
        // the user's accounted balance.
        balances[msg.sender] += amount;
    }
}
