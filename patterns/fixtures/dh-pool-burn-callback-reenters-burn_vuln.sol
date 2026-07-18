// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IStrategy {
    function burnHook(address receiver, bytes32 key, uint256 amount, uint256 lastTS) external;
}

interface IToken { function transfer(address to, uint256 amt) external returns (bool); }

contract RebalancerVuln {
    struct Pool { address strategy; uint256 totalSupply; uint256 reserveQuote; address quote; }
    mapping(bytes32 => Pool) public pools;

    function mint(bytes32 key, uint256 amount) external { pools[key].totalSupply += amount; }

    // Vuln: burnHook fires without reentrancy guard; strategy is attacker-chosen.
    function burn(bytes32 key, uint256 amount) external returns (uint256 out) {
        Pool storage p = pools[key];
        uint256 ts = p.totalSupply;
        out = (p.reserveQuote * amount) / ts;
        IStrategy(p.strategy).burnHook(msg.sender, key, amount, ts);
        p.totalSupply = ts - amount;
        p.reserveQuote -= out;
        IToken(p.quote).transfer(msg.sender, out);
    }
}
