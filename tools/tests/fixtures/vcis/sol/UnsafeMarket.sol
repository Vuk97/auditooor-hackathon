// SPDX-License-Identifier: MIT
// VCIS TEST FIXTURE - UNSAFE (self-settled take class)
// take() nets a transfer to ZERO while still crediting creditOf[buyer].
// The synthesised solvency-floor property MUST be violated by this contract.
pragma solidity ^0.8.0;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

library SafeTransferLib {
    function safeTransfer(address token, address to, uint256 amount) internal {
        IERC20(token).transfer(to, amount);
    }
    function safeTransferFrom(address token, address from, address to, uint256 amount) internal {
        IERC20(token).transferFrom(from, to, amount);
    }
}

/// @dev UNSAFE: a borrower can call take() as BOTH buyer AND seller (from==to).
///      Net token flow to protocol is ZERO but creditOf[buyer] increments.
///      Solvency floor: loanToken.balanceOf(protocol) >= withdrawable
///      will be violated after enough self-settle calls.
contract UnsafeMarket {
    address public loanToken;
    mapping(address => uint256) public creditOf;   // liability: credit-side
    mapping(address => uint256) public debtOf;     // debit-side only
    uint256 public totalWithdrawable;

    constructor(address _loanToken) {
        loanToken = _loanToken;
    }

    // BUG: buyer==seller => net transfer to protocol is 0 but credit increments.
    function take(address buyer, address seller, uint256 units) external {
        creditOf[buyer] += units;      // credit-side liability grows
        debtOf[seller] += units;       // debit-side
        totalWithdrawable += units;    // total owed to lenders grows
        // BUG: transfer is from seller -> protocol -> buyer in one step
        // but if buyer==seller the net balance change to protocol is 0.
        SafeTransferLib.safeTransferFrom(loanToken, seller, address(this), units);
        // In the buggy variant: immediately send back so protocol holds nothing.
        SafeTransferLib.safeTransfer(loanToken, buyer, units);
        // After this: protocol.balanceOf(loanToken) unchanged, but totalWithdrawable += units.
        // => solvency floor VIOLATED.
    }

    function flashLoan(address token, address to, uint256 amount) external {
        SafeTransferLib.safeTransfer(token, to, amount);
    }
}
