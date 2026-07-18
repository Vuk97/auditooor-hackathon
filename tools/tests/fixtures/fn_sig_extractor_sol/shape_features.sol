// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Wave-11 fixture for shape_features extraction. Each function is crafted
// to exercise a distinct feature of _solidity_shape_features() so that
// shape_hash_fine distinguishes them.

interface IThing {
    function poke() external;
}

contract ShapeFeatures {
    address public owner;
    uint256 public counter;
    mapping(address => uint256) public balances;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier nonReentrant() {
        _;
    }

    // Pure storage-write function: 3 top-level writes, no external calls,
    // no guards, no require/revert, no assembly.
    function multiWrite(uint256 a, uint256 b) external {
        counter = a;
        balances[msg.sender] = b;
        owner = msg.sender;
    }

    // External-call heavy function: 3 external calls, no writes.
    function multiExternalCall(address t1, address t2) external {
        IThing(t1).poke();
        (bool ok1, ) = t2.call("");
        require(ok1, "call failed");
        payable(t2).transfer(0);
    }

    // Authority + reentrancy guarded; mixes a require and a write.
    function guardedWrite(uint256 v) external onlyOwner nonReentrant {
        require(v != 0, "zero");
        counter = v;
    }

    // Function with inline assembly.
    function asmEcho(uint256 x) external pure returns (uint256 y) {
        assembly {
            y := x
        }
    }

    // Plain view with no writes / no external calls / no guards.
    function readCounter() external view returns (uint256) {
        return counter;
    }
}
