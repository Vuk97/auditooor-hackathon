// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract StakeV2ManagerAccessControlClean {
    address public owner;
    mapping(address => bool) public managers;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function addManager(address _manager) external onlyOwner {
        require(!managers[_manager], "Manager already exists");
        managers[_manager] = true;
    }

    function removeManager(address _manager) external onlyOwner {
        require(managers[_manager], "Manager does not exist");
        managers[_manager] = false;
    }
}

contract StakeV2OnlyManagerClean {
    mapping(address => bool) public managers;

    modifier onlyManager() {
        require(managers[msg.sender], "not manager");
        _;
    }

    function addManager(address _manager) external onlyManager {
        managers[_manager] = true;
    }

    function removeManager(address _manager) external onlyManager {
        managers[_manager] = false;
    }
}
