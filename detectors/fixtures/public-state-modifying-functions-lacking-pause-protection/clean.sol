// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PublicStateModifyingFunctionsLackingPauseProtectionClean {
    bool internal _paused;
    mapping(address => uint256) public balanceOf;
    uint256 public totalDeposits;

    modifier whenNotPaused() {
        require(!_paused, "paused");
        _;
    }

    function pause() external {
        _paused = true;
    }

    function unpause() external {
        _paused = false;
    }

    function paused() external view returns (bool) {
        return _paused;
    }

    function deposit(uint256 amount) external whenNotPaused {
        balanceOf[msg.sender] += amount;
        totalDeposits += amount;
    }

    function withdraw(uint256 amount) external whenNotPaused {
        balanceOf[msg.sender] -= amount;
        totalDeposits -= amount;
    }
}
