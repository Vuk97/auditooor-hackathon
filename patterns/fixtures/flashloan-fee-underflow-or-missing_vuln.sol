// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Min {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

interface IFlashReceiver {
    function onFlashLoanReceived(uint256 amount) external;
}

// VULN: contract exposes a flash-fee knob in storage but none of its
// flashloan entry points charge or propagate it. Every function body is
// missing every one of the fee-charging idioms the pattern enumerates.
contract FlashloanFeeUnderflowOrMissingVuln {
    address public token;
    // Flash-fee knob — advertised in storage but never actually applied.
    uint256 public flashFee;        // precondition match
    uint256 public flashloanFee;    // precondition match (alt name)
    uint256 public feeRate;         // precondition match (alt name)
    uint256 public flashLoanRate;   // precondition match (alt name)

    constructor(address _token, uint256 _fee) {
        token = _token;
        flashFee = _fee;
        flashloanFee = _fee;
        feeRate = _fee;
        flashLoanRate = _fee;
    }

    // VULN: no fee math, no fee binding, no fee accessor call. Free flashloans.
    function flashLoan(uint256 amount) external {
        IERC20Min(token).transfer(msg.sender, amount);
        IFlashReceiver(msg.sender).onFlashLoanReceived(amount);
        IERC20Min(token).transferFrom(msg.sender, address(this), amount);
    }

    // VULN: alternative entry name, same problem.
    function flashBorrow(uint256 amount) external {
        IERC20Min(token).transfer(msg.sender, amount);
        IFlashReceiver(msg.sender).onFlashLoanReceived(amount);
        IERC20Min(token).transferFrom(msg.sender, address(this), amount);
    }

    // VULN: executor style — still no fee.
    function executeFlashLoan(uint256 amount) external {
        IERC20Min(token).transfer(msg.sender, amount);
        IFlashReceiver(msg.sender).onFlashLoanReceived(amount);
        IERC20Min(token).transferFrom(msg.sender, address(this), amount);
    }

    // VULN: ERC-3156-style callback dispatcher that forwards principal
    // but never constructs a fee parameter for the receiver.
    function onFlashLoan(address, address, uint256 amount, bytes calldata) external returns (bytes32) {
        IERC20Min(token).transferFrom(msg.sender, address(this), amount);
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }

    // VULN: doFlashLoan entry variant — also missing fee.
    function doFlashLoan(uint256 amount) external {
        IERC20Min(token).transfer(msg.sender, amount);
        IFlashReceiver(msg.sender).onFlashLoanReceived(amount);
        IERC20Min(token).transferFrom(msg.sender, address(this), amount);
    }
}
