// SPDX-License-Identifier: MIT
// Fixture: unsafe-uint-to-int-cast — VULNERABLE
// Detector MUST fire on every function here.
pragma solidity ^0.8.20;

contract UnsafeUintToIntCastVuln {
    uint256 public cumulativeFunding;
    mapping(address => uint256) public fundingAtEntry;
    mapping(address => int256) public pnl;

    // VULN: bare int256(uint) cast — reinterprets bits, no range check.
    // When cumulativeFunding >= 2**255 the result is negative and the
    // subtraction wraps, silently producing wrong P&L.
    function settle(address trader) external {
        int256 delta = int256(cumulativeFunding) - int256(fundingAtEntry[trader]);
        pnl[trader] += delta;
    }

    // VULN: short-form int() cast on a uint arg.
    function signedDiff(uint256 a, uint256 b) external pure returns (int256) {
        return int256(a) - int256(b);
    }

    // VULN: sized int128(uint128) — still a reinterpret, same sign-flip risk.
    function tickDelta(uint128 u) external pure returns (int128) {
        return int128(u);
    }

    // VULN: C-style `(int256) x +` form used inside arithmetic expressions.
    function marginUpdate(uint256 gross, uint256 fee) external pure returns (int256) {
        return (int256) (gross) - (int256) (fee);
    }
}
