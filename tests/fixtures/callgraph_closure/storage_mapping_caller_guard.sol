// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (h): storage-mapping caller-identity guard. SSV-surfaced shape:
//   require(validators[validatorId].contractAddress == msg.sender);
// inside a modifier (or fn body). The caller identity is compared against a
// value READ FROM A STORAGE MAPPING/STRUCT FIELD (validators[k].field), not a
// plain state scalar. has_guard_in_closure(removeValidator) must return True.
//
// `unguardedRemove()` is the NEGATIVE control: same storage write, no
// caller-identity compare -> must stay unguarded (no widening).
//
// `valueBoundOnly()` is the second NEGATIVE: a numeric-bound require that reads
// a storage mapping value but does NOT compare against msg.sender -> unguarded.
//
// Mutation hook: tests delete the `require(...)` tagged // AUTH-TARGET to
// confirm `removeValidator` flips True -> False (non-vacuity).

// Context base so a fn can read the caller INDIRECTLY via _msgSender() and cache
// it into a local - the shape that isolates signal (4) (caller-vs-storage) from
// signal (1) (literal msg.sender read on the SAME node) and signal (3)
// (_msgSender() accessor call on the SAME node).
contract _CtxBase {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }
}

contract StorageMappingCallerGuard is _CtxBase {
    struct Validator {
        address contractAddress;
        uint256 balance;
    }

    mapping(bytes32 => Validator) public validators;
    uint256 public total;

    modifier onlyValidatorOwner(bytes32 validatorId) {
        require(validators[validatorId].contractAddress == msg.sender, "not owner"); // AUTH-TARGET
        _;
    }

    // POSITIVE: storage-mapping caller-identity guard via modifier. guarded=True.
    function removeValidator(bytes32 validatorId) external onlyValidatorOwner(validatorId) {
        delete validators[validatorId];
    }

    // POSITIVE: same guard inline in the body. guarded=True.
    function removeValidatorInline(bytes32 validatorId) external {
        require(msg.sender == validators[validatorId].contractAddress, "not owner");
        delete validators[validatorId];
    }

    // NEGATIVE: no caller-identity compare at all. guarded=False.
    function unguardedRemove(bytes32 validatorId) external {
        delete validators[validatorId];
    }

    // NEGATIVE: a numeric-bound require reading a storage value, no msg.sender.
    function valueBoundOnly(bytes32 validatorId, uint256 amount) external {
        require(amount <= validators[validatorId].balance, "too big");
        total += amount;
    }

    // POSITIVE (SIGNAL-4-ISOLATING): the caller is cached from _msgSender() on a
    // PRIOR line, then compared against the storage struct field. The require node
    // has NO literal msg.sender read (so signal (1) cannot fire) and calls NO
    // accessor on that node (so signal (3) cannot fire). ONLY signal (4)
    // (caller-alias-vs-storage-read) can credit this -> guarded=True. Removing
    // signal (4)'s call site flips this fn True -> False (non-vacuity proof).
    function removeValidatorCachedCaller(bytes32 validatorId) external {
        address who = _msgSender();
        require(validators[validatorId].contractAddress == who, "not owner"); // SIG4-ISOLATING-TARGET
        delete validators[validatorId];
    }

    // NEGATIVE (signal-4 over-credit guard): a cached LOCAL that is NOT the caller
    // (a function parameter) compared against the storage field must NOT be
    // credited - the alias set only seeds from msg.sender / _msgSender().
    function cachedNonCaller(bytes32 validatorId, address arbitrary) external {
        address who = arbitrary;
        require(validators[validatorId].contractAddress == who, "x");
        delete validators[validatorId];
    }
}
