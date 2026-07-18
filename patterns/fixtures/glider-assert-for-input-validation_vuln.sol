pragma solidity ^0.8.0;

contract AssertInputVuln {
    uint256 public cap = 100;
    uint256 public value;

    function setValue(uint256 v) external {
        assert(v < cap);
        value = v;
    }

    function getValue() external view returns (uint256) {
        return value;
    }
}