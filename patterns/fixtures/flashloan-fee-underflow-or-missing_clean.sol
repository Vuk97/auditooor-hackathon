// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Min {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

interface IFlashReceiver {
    function onFlashLoanReceived(uint256 amount, uint256 fee) external;
}

// CLEAN: every flashloan entry point computes a fee, binds it to a local,
// propagates it into the callback, and requires the repayment to cover
// principal + fee. The body of each function references at least one of
// the pattern's fee-charging idioms, so `body_not_contains_regex`
// evaluates false and the detector must not fire.
contract FlashloanFeeUnderflowOrMissingClean {
    error FeeRoundsToZero();

    address public token;
    uint256 public flashFee;        // 9 = 0.09% in basis points (1e4 denom)
    uint256 public flashloanFee;
    uint256 public feeRate;
    uint256 public flashLoanRate;

    uint256 internal constant FEE_DENOM = 1e4;

    constructor(address _token, uint256 _feeBps) {
        token = _token;
        flashFee = _feeBps;
        flashloanFee = _feeBps;
        feeRate = _feeBps;
        flashLoanRate = _feeBps;
    }

    // Accessor — its NAME contains `flashFee` so any function that calls it
    // trips the positive fee-charging regex branch `flashFee\s*\(`.
    function _flashFee(uint256 amount) internal view returns (uint256) {
        uint256 fee = (amount * flashFee) / FEE_DENOM;
        if (amount > 0 && fee == 0) revert FeeRoundsToZero();
        return fee;
    }

    // CLEAN: uses `_flashFee(...)` (body-regex hit).
    function flashLoan(uint256 amount) external {
        uint256 fee = _flashFee(amount);
        uint256 pre = IERC20Min(token).balanceOf(address(this));
        IERC20Min(token).transfer(msg.sender, amount);
        IFlashReceiver(msg.sender).onFlashLoanReceived(amount, fee);
        IERC20Min(token).transferFrom(msg.sender, address(this), amount + fee);
        require(IERC20Min(token).balanceOf(address(this)) >= pre + fee, "fee not paid");
    }

    // CLEAN: inline fee math (`fee *` / `fee =` regex hits).
    function flashBorrow(uint256 amount) external {
        uint256 fee = (amount * flashloanFee) / FEE_DENOM;
        if (amount > 0 && fee == 0) revert FeeRoundsToZero();
        uint256 pre = IERC20Min(token).balanceOf(address(this));
        IERC20Min(token).transfer(msg.sender, amount);
        IFlashReceiver(msg.sender).onFlashLoanReceived(amount, fee);
        IERC20Min(token).transferFrom(msg.sender, address(this), amount + fee);
        require(IERC20Min(token).balanceOf(address(this)) >= pre + fee, "fee not paid");
    }

    // CLEAN: uses a local `feeAmount` name (body-regex hit on `feeAmount`).
    function executeFlashLoan(uint256 amount) external {
        uint256 feeAmount = (amount * feeRate) / FEE_DENOM;
        if (amount > 0 && feeAmount == 0) revert FeeRoundsToZero();
        uint256 pre = IERC20Min(token).balanceOf(address(this));
        IERC20Min(token).transfer(msg.sender, amount);
        IFlashReceiver(msg.sender).onFlashLoanReceived(amount, feeAmount);
        IERC20Min(token).transferFrom(msg.sender, address(this), amount + feeAmount);
        require(IERC20Min(token).balanceOf(address(this)) >= pre + feeAmount, "fee not paid");
    }

    // CLEAN: ERC-3156 callback receives the fee explicitly and propagates
    // it. The body references `fee =` and `* flashloanRate` — both
    // positive hits against the body regex.
    function onFlashLoan(address, address, uint256 amount, bytes calldata) external returns (bytes32) {
        uint256 fee = (amount * flashLoanRate) / FEE_DENOM;
        if (amount > 0 && fee == 0) revert FeeRoundsToZero();
        IERC20Min(token).transferFrom(msg.sender, address(this), amount + fee);
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }

    // CLEAN: uses `feeToReceive` local name (body-regex hit on `feeToReceive`).
    function doFlashLoan(uint256 amount) external {
        uint256 feeToReceive = (amount * flashLoanRate) / FEE_DENOM;
        if (amount > 0 && feeToReceive == 0) revert FeeRoundsToZero();
        uint256 pre = IERC20Min(token).balanceOf(address(this));
        IERC20Min(token).transfer(msg.sender, amount);
        IFlashReceiver(msg.sender).onFlashLoanReceived(amount, feeToReceive);
        IERC20Min(token).transferFrom(msg.sender, address(this), amount + feeToReceive);
        require(IERC20Min(token).balanceOf(address(this)) >= pre + feeToReceive, "fee not paid");
    }
}
