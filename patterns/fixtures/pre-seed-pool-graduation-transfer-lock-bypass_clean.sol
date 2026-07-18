// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PreSeedPoolGraduationTransferLockBypassClean {
    mapping(address => uint256) public balanceOf;
    address public pair;
    bool public graduated;

    function setPair(address p) external { pair = p; }
    function graduate() external { graduated = true; }

    function _transfer(address from, address to, uint256 amount) external {
        require(graduated, "locked");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
}
