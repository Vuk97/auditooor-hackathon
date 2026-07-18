// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC777Recipient {
    function tokensReceived(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes calldata userData,
        bytes calldata operatorData
    ) external;
}

interface IFlashLoanReceiver {
    function receiveFlashLoan(uint256 amount, bytes calldata data) external;
}

interface IERC20Like {
    function transfer(address, uint256) external returns (bool);
}

/// VULN: exposes an unguarded view that returns sharePrice derived from live
/// balance/totalSupply state, AND exposes a flash-loan callback surface
/// (so an external integrator quoting this view inside receiveFlashLoan
/// observes a mid-mutation deflated price).
contract ReadOnlyReentrancyPoolVuln {
    mapping(address => uint256) public balance;   // per-LP balance (accounting state)
    uint256 public totalSupply;                   // LP share supply (accounting state)
    uint256 public reserve;                       // underlying reserve (accounting state)
    IERC20Like public token;

    // Flash-loan path: decrements reserve BEFORE calling the receiver and
    // only restores it AFTER the callback returns. During the callback
    // reserve is deflated — perfect read-only reentrancy surface.
    function flashLoan(address receiver, uint256 amount, bytes calldata data) external {
        reserve -= amount;
        token.transfer(receiver, amount);
        IFlashLoanReceiver(receiver).receiveFlashLoan(amount, data);
        reserve += amount;
    }

    // VULN: public view reads live reserve/totalSupply WITHOUT any
    // nonReentrant-view guard. A lending market quoting this as an oracle
    // during the callback sees reserve mid-mutation.
    function getSharePrice() external view returns (uint256) {
        if (totalSupply == 0) return 1e18;
        return (reserve * 1e18) / totalSupply;
    }

    // VULN: second unguarded getter on the same live state.
    function pricePerShare() public view returns (uint256) {
        if (totalSupply == 0) return 1e18;
        return (reserve * 1e18) / totalSupply;
    }
}
