// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IStrategyC {
    function burnHook(address receiver, bytes32 key, uint256 amount, uint256 lastTS) external;
}

interface ITokenC { function transfer(address to, uint256 amt) external returns (bool); }

contract RebalancerClean {
    struct Pool { address strategy; uint256 totalSupply; uint256 reserveQuote; address quote; }
    mapping(bytes32 => Pool) public pools;
    bool private _locked;

    modifier nonReentrant() { require(!_locked, "RE"); _locked = true; _; _locked = false; }

    function mint(bytes32 key, uint256 amount) external nonReentrant { pools[key].totalSupply += amount; }

    // Clean: nonReentrant guard AND settle accounting before the hook fires.
    function burn(bytes32 key, uint256 amount) external nonReentrant returns (uint256 out) {
        Pool storage p = pools[key];
        uint256 ts = p.totalSupply;
        out = (p.reserveQuote * amount) / ts;
        p.totalSupply = ts - amount;
        p.reserveQuote -= out;
        IStrategyC(p.strategy).burnHook(msg.sender, key, amount, ts);
        ITokenC(p.quote).transfer(msg.sender, out);
    }
}
