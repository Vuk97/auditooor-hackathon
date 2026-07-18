// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PreSeedPoolGraduationTransferLockBypassVuln {
    mapping(address => uint256) public balanceOf;
    address public pair;
    bool public graduated;

    function setPair(address p) external { pair = p; }
    function graduate() external { graduated = true; }

    function _transfer(address from, address to, uint256 amount) external {
        // VULN: exemption for pair even before graduation.
        if (to != pair) {
            require(graduated, "locked");
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
}
