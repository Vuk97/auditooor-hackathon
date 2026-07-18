// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (g): OpenZeppelin onlyOwner -> _checkOwner() -> owner()-revert
// indirection. This mirrors OZ OwnableUpgradeable: the `onlyOwner` modifier
// BODY is just `_checkOwner();` (NO direct msg.sender in that node), and
// `_checkOwner()` reverts via `require(owner() == _msgSender(), ...)`. The
// caller is read INDIRECTLY through Context._msgSender(), not a literal
// msg.sender, so the pre-refinement default predicate FALSE-flagged
// `rescueERC20` as unguarded. has_guard_in_closure(rescueERC20) must now
// return True (the closure folds the modifier body -> _checkOwner body, where
// either the _checkOwner CALL or the owner()/_msgSender() accessor-compare in
// the require is recognised as a caller-identity guard).
//
// `valueBoundOnly()` is the NEGATIVE control: a require on a numeric bound is
// NOT a caller-identity guard and must stay unguarded (no widening).
//
// `permissionless()` is the second NEGATIVE: a genuinely open fn (no modifier,
// no authz helper, no caller compare) must stay unguarded.
//
// Mutation hook: tests delete the `require(...)` in `_checkOwner` (tagged
// // AUTH-TARGET) to confirm `rescueERC20` flips True -> False (non-vacuity).

abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }
}

abstract contract Ownable is Context {
    address private _owner;

    constructor() {
        _owner = _msgSender();
    }

    function owner() public view virtual returns (address) {
        return _owner;
    }

    function _checkOwner() internal view virtual {
        require(owner() == _msgSender(), "Ownable: caller is not the owner"); // AUTH-TARGET
    }

    modifier onlyOwner() {
        _checkOwner();
        _;
    }
}

contract OzGuardedVault is Ownable {
    uint256 public x;

    // POSITIVE: owner-gated via OZ indirection. Must be guarded=True.
    function rescueERC20(address, address, uint256 amount) external onlyOwner {
        x += amount;
    }

    // NEGATIVE: value-bound require only. Must stay guarded=False.
    function valueBoundOnly(uint256 amount) external {
        require(amount <= 1000, "too big");
        x += amount;
    }

    // NEGATIVE: genuinely permissionless. Must stay guarded=False.
    function permissionless(uint256 amount) external {
        x += amount;
    }
}
