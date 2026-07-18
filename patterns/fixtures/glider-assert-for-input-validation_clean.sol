pragma solidity ^0.8.0;

contract AssertInputClean {
    uint256 public cap = 100;
    uint256 public value;

    function setValue(uint256 v) external {
        require(v < cap, "value exceeds cap");
        value = v;
    }

    function getValue() external view returns (uint256) {
        return value;
    }
}