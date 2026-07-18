// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ECONOMIC STORAGE-VALUE sink fixture (sink-taxonomy extension / P1).
//
// Models the SSV operatorEthVUnits[id] +=/delete accounting axis. A direct
// WRITE to an economic mapping (`operatorEthVUnits` - a units/value accounting
// var) moves protocol value, yet the call-based value-flow classifier
// (transfer/mint/burn/...) is BLIND to it. The storage-value sink extension must
// surface each economic write as a `storage-value` sink.
//
// Two writer shapes:
//   - `accrueUnits`:  operatorEthVUnits[id] += amount   (compound-assign write)
//   - `removeOperator`: delete operatorEthVUnits[id]    (delete write)
// Plus a non-economic write (`lastSeen[id] = now`) that must NOT be tagged
// (its name is not a value noun) -> proves the heuristic is selective.
//
// `removeOperator` is role-gated by onlyRegistrar; with Part-1 D-connect the
// storage-value sink on that path is closure-corrected to unguarded=false, while
// the permissionless `accrueUnits` stays unguarded=true.
contract EconStorage {
    mapping(uint64 => uint256) public operatorEthVUnits; // economic units mapping
    mapping(uint64 => uint256) public lastSeen;          // NOT economic (a timestamp)
    address public registrar;

    constructor() {
        registrar = msg.sender;
    }

    modifier onlyRegistrar() {
        require(msg.sender == registrar, "not registrar");
        _;
    }

    // PERMISSIONLESS economic write -> storage-value sink, genuinely unguarded.
    function accrueUnits(uint64 id, uint256 amount) external {
        operatorEthVUnits[id] += amount;
        lastSeen[id] = block.timestamp; // non-economic write (must not be tagged)
    }

    // ROLE-GATED economic write (delete) -> storage-value sink, closure-guarded.
    function removeOperator(uint64 id) external onlyRegistrar {
        delete operatorEthVUnits[id];
    }
}
