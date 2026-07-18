// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — secure reference for the
/// flashloan-no-fee-charged detector. The detector MUST NOT fire on
/// this contract. Every flashloan entry point computes a fee via at
/// least one of the patterns the detector's negative regex enumerates
/// (feeBps / flashFee / _calculateFee / fee = / fee * / amount + fee /
/// premium / flashloanPremium) and requires the repayment to cover it.

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
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
    function onFlashLoanReceived(uint256 amount, uint256 fee) external;
}

contract FlashloanNoFeeClean {
    using SafeERC20 for IERC20;

    error FeeRoundsToZero();

    IERC20 public token;
    uint256 public feeBps; // 9 = 0.09% bps (denom 1e4)
    uint256 public flashFee;
    uint256 public flashloanPremium;
    uint256 public premium;

    uint256 internal constant FEE_DENOM = 1e4;

    constructor(IERC20 _token, uint256 _feeBps) {
        token = _token;
        feeBps = _feeBps;
        flashFee = _feeBps;
        flashloanPremium = _feeBps;
        premium = _feeBps;
    }

    // Explicit fee accessor — its name hits `_calculateFee` and `flashFee`
    // in the positive branch of the body regex.
    function _calculateFee(uint256 amount) internal view returns (uint256) {
        uint256 fee = (amount * feeBps) / FEE_DENOM;
        if (amount > 0 && fee == 0) revert FeeRoundsToZero();
        return fee;
    }

    /// CLEAN: uses `_calculateFee(...)` and binds a local `fee =`.
    function flashLoan(uint256 amount) external {
        uint256 fee = _calculateFee(amount);
        uint256 pre = token.balanceOf(address(this));
        token.safeTransfer(msg.sender, amount);
        IFlashReceiver(msg.sender).onFlashLoanReceived(amount, fee);
        token.safeTransferFrom(msg.sender, address(this), amount + fee);
        require(token.balanceOf(address(this)) >= pre + fee, "fee not paid");
    }

    /// CLEAN: inline `fee *` math and `amount + fee` repayment.
    function flashBorrow(uint256 amount) external {
        uint256 fee = (amount * feeBps) / FEE_DENOM;
        if (amount > 0 && fee == 0) revert FeeRoundsToZero();
        uint256 pre = token.balanceOf(address(this));
        token.transfer(msg.sender, amount);
        IFlashReceiver(msg.sender).onFlashLoanReceived(amount, fee);
        token.transferFrom(msg.sender, address(this), amount + fee);
        require(token.balanceOf(address(this)) >= pre + fee, "fee not paid");
    }

    /// CLEAN: Aave-style `premium` naming — hits the `premium` token.
    function executeFlashLoan(uint256 amount) external {
        uint256 premiumAmt = (amount * premium) / FEE_DENOM;
        if (amount > 0 && premiumAmt == 0) revert FeeRoundsToZero();
        uint256 pre = token.balanceOf(address(this));
        token.safeTransfer(msg.sender, amount);
        IFlashReceiver(msg.sender).onFlashLoanReceived(amount, premiumAmt);
        token.safeTransferFrom(msg.sender, address(this), amount + premiumAmt);
        require(token.balanceOf(address(this)) >= pre + premiumAmt, "fee not paid");
    }

    /// CLEAN: `flashloanPremium` accessor hit + `fee =` local binding.
    function flash(uint256 amount) external {
        uint256 fee = (amount * flashloanPremium) / FEE_DENOM;
        if (amount > 0 && fee == 0) revert FeeRoundsToZero();
        uint256 pre = token.balanceOf(address(this));
        token.safeTransfer(msg.sender, amount);
        IFlashReceiver(msg.sender).onFlashLoanReceived(amount, fee);
        token.safeTransferFrom(msg.sender, address(this), amount + fee);
        require(token.balanceOf(address(this)) >= pre + fee, "fee not paid");
    }

    /// CLEAN: internal `_flashLoan` — `flashFee` accessor + `fee *`.
    function _flashLoan(uint256 amount) external {
        uint256 fee = (amount * flashFee) / FEE_DENOM;
        if (amount > 0 && fee == 0) revert FeeRoundsToZero();
        uint256 pre = token.balanceOf(address(this));
        token.safeTransfer(msg.sender, amount);
        IFlashReceiver(msg.sender).onFlashLoanReceived(amount, fee);
        token.safeTransferFrom(msg.sender, address(this), amount + fee);
        require(token.balanceOf(address(this)) >= pre + fee, "fee not paid");
    }
}
