// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: FPC-style token. _transfer burns a fraction of tokens whenever
// `to == pancakePair`. This shrinks the pair reserve and inflates FPC
// price across subsequent swaps.
contract FPCTokenVuln {
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;
    address public pancakePair;
    address public constant deadAddress = 0x000000000000000000000000000000000000dEaD;

    function setPair(address p) external { pancakePair = p; }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        balances[from] -= amount;
        // BUG: burn-on-land when destination is the AMM pair
        if (to == pancakePair) {
            uint256 burnAmt = amount / 2;  // 50% burn on pair receipt
            balances[deadAddress] += burnAmt;
            balances[to] += (amount - burnAmt);
        } else {
            balances[to] += amount;
        }
    }
}
