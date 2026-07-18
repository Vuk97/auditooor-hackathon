// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// flashloan-no-fee-charged detector. DO NOT DEPLOY.
///
/// Every flashloan entry point below sends principal outbound via
/// safeTransfer / transfer / _transferToReceiver / _sendFunds but
/// contains no fee-charging idiom in its body (no `feeBps`, no
/// `flashFee`, no `_calculateFee`, no `fee = ...`, no `fee *`, no
/// `amount + <anything>fee`, no `premium`, no `flashloanPremium`).
/// Each entry is a free-loan surface.

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
}

library SafeERC20 {
    function safeTransfer(IERC20 tk, address to, uint256 amt) internal {
        require(tk.transfer(to, amt), "transfer failed");
    }
    function safeTransferFrom(IERC20 tk, address from, address to, uint256 amt) internal {
        require(tk.transferFrom(from, to, amt), "transferFrom failed");
    }
}

interface IFlashReceiver {
    function onFlashLoanReceived(uint256 amount) external;
}

contract FlashloanNoFeeVuln {
    using SafeERC20 for IERC20;

    IERC20 public token;

    constructor(IERC20 _token) {
        token = _token;
    }

    /// VULN: canonical entry — SafeERC20.safeTransfer, no fee math.
    function flashLoan(uint256 amount) external {
        token.safeTransfer(msg.sender, amount);
        IFlashReceiver(msg.sender).onFlashLoanReceived(amount);
        token.safeTransferFrom(msg.sender, address(this), amount);
    }

    /// VULN: Balancer-style entry — direct token.transfer, no fee.
    function flashBorrow(uint256 amount) external {
        token.transfer(msg.sender, amount);
        IFlashReceiver(msg.sender).onFlashLoanReceived(amount);
        token.transferFrom(msg.sender, address(this), amount);
    }

    /// VULN: executor variant — protocol-internal transfer helper, no fee.
    function executeFlashLoan(uint256 amount) external {
        _transferToReceiver(msg.sender, amount);
        IFlashReceiver(msg.sender).onFlashLoanReceived(amount);
        token.transferFrom(msg.sender, address(this), amount);
    }

    /// VULN: Uniswap V3-minimal entry name `flash` — _sendFunds helper, no fee.
    function flash(uint256 amount) external {
        _sendFunds(msg.sender, amount);
        IFlashReceiver(msg.sender).onFlashLoanReceived(amount);
        token.transferFrom(msg.sender, address(this), amount);
    }

    /// VULN: internal implementation wrapped by a public shim — also free.
    function _flashLoan(uint256 amount) external {
        token.safeTransfer(msg.sender, amount);
        IFlashReceiver(msg.sender).onFlashLoanReceived(amount);
        token.safeTransferFrom(msg.sender, address(this), amount);
    }

    // Internal helpers — names tripped by the positive body regex.
    function _transferToReceiver(address to, uint256 amt) internal {
        token.transfer(to, amt);
    }

    function _sendFunds(address to, uint256 amt) internal {
        token.transfer(to, amt);
    }
}
