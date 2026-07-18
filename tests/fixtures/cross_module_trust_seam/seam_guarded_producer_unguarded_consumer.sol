// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Case 1 (SEAM fires -> 1).
// Module B (Auth) owns the caller-identity guard. Module A (Vault) TRUSTS that
// `rate` was set through a guarded producer and does NOT re-check at its sink.
//   (a) guarded producer: setRate() has a caller-identity guard (writer).
//   (b) consumer sink pokeRate() does NOT re-check `rate`.
//   (c) pokeRate() is a public UNGUARDED entrypoint reaching the sink (bypass).
contract Auth {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function _requireOwner() internal view {
        require(msg.sender == owner, "not owner");
    }
}

contract Vault is Auth {
    uint256 public rate; // V

    // GUARDED producer of V (writer): the caller-identity guard lives in Auth.
    function setRate(uint256 newRate) external {
        _requireOwner();
        rate = newRate;
    }

    // UNGUARDED consumer sink of V: reads `rate`, no re-check, itself a public
    // bypass entrypoint.
    function pokeRate() external view returns (uint256) {
        return rate * 2;
    }
}
