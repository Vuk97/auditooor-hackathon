// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract StakeV2ManagerAccessControlPositive {
    mapping(address => bool) public managers;

    function addManager(address _manager) external {
        require(!managers[_manager], "Manager already exists");
        managers[_manager] = true;
    }

    function removeManager(address _manager) external {
        require(managers[_manager], "Manager does not exist");
        managers[_manager] = false;
    }
}

contract StakeV2ManagerExistsModifierPositive {
    mapping(address => bool) public managers;

    modifier managerExists(address _manager) {
        require(managers[_manager], "Manager does not exist");
        _;
    }

    function addManager(address _manager) external managerExists(_manager) {
        managers[_manager] = true;
    }

    function removeManager(address _manager) external managerExists(_manager) {
        managers[_manager] = false;
    }
}
