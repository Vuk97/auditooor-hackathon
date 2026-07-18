// SPDX-License-Identifier: MIT
// VCIS TEST FIXTURE - SAFE (conservation holds)
// A correctly implemented market: every credit increment is backed by a real
// token inflow.  The synthesised solvency-floor property MUST hold here.
pragma solidity ^0.8.0;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

library SafeTransferLib {
    function safeTransfer(address token, address to, uint256 amount) internal {
        IERC20(token).transfer(to, amount);
    }
    function safeTransferFrom(address token, address from, address to, uint256 amount) internal {
        IERC20(token).transferFrom(from, to, amount);
    }
}

/// @dev SAFE: every credit increment is matched by a real inflow from a DIFFERENT
///      address (buyer != seller enforced).  Protocol balance >= totalWithdrawable.
contract SafeMarket {
    address public loanToken;
    mapping(address => uint256) public creditOf;
    mapping(address => uint256) public debtOf;
    uint256 public totalWithdrawable;

    constructor(address _loanToken) {
        loanToken = _loanToken;
    }

    function take(address buyer, address seller, uint256 units) external {
        require(buyer != seller, "no self-settle");   // safety guard
        creditOf[buyer] += units;
        debtOf[seller] += units;
        totalWithdrawable += units;
        // Real inflow: protocol receives units from seller.
        SafeTransferLib.safeTransferFrom(loanToken, seller, address(this), units);
        // No outflow in take() - balance grows by exactly units.
    }

    function flashLoan(address token, address to, uint256 amount) external {
        SafeTransferLib.safeTransfer(token, to, amount);
    }
}
