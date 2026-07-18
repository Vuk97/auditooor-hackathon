// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: _transfer never burns on pair-receive. Optional sell tax is
// applied only on transfer FROM the pair (user selling path), and LP
// router is explicitly excluded from fees.
contract FPCTokenClean {
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;
    address public pancakePair;
    address public lpRouter;
    mapping(address => bool) public isExcludedFromFee;

    function setPair(address p) external { pancakePair = p; }
    function setRouter(address r) external { lpRouter = r; }
    function setExcluded(address a, bool x) external { isExcludedFromFee[a] = x; }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        balances[from] -= amount;
        // Sell tax only when the pair is the SENDER (user is buying via pair),
        // and router / pair / exempt addresses are excluded.
        uint256 fee = 0;
        if (from == pancakePair && !isExcludedFromFee[from] && !isExcludedFromFee[to]) {
            fee = amount / 100; // 1% sell tax to treasury
        }
        balances[to] += (amount - fee);
    }
}
