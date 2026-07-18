// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract MissingAuthorityRegistry {
    mapping(bytes32 => address) public adapters;
    address public owner;

    constructor(address initialOwner) {
        owner = initialOwner;
    }

    function setAdapter(bytes32 key, address adapter) external {
        require(adapter != address(0), "zero adapter");
        adapters[key] = adapter;
    }
}

contract WrongActorGateway {
    address public owner;
    address public gateway;

    constructor(address initialOwner) {
        owner = initialOwner;
    }

    function setGateway(address newGateway) external {
        require(tx.origin == owner, "origin only");
        gateway = newGateway;
    }
}

contract CallerSuppliedAuthorityDomain {
    address public manager;

    modifier onlyConfiguredAdmin(address adminContractAddress) {
        require(IAdminDomain(adminContractAddress).hasRole(msg.sender), "not admin");
        _;
    }

    function changeManager(address adminContractAddress, address newManager)
        external
        onlyConfiguredAdmin(adminContractAddress)
    {
        manager = newManager;
    }
}

interface IAdminDomain {
    function hasRole(address account) external view returns (bool);
}

contract UnguardedRoleMutation {
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    mapping(bytes32 => mapping(address => bool)) public roles;

    function grantOperator(address account) external {
        roles[OPERATOR_ROLE][account] = true;
    }
}

contract NonAuthorityGuardedMarketConfig {
    bool public paused;
    mapping(uint256 => address) public marketConfig;

    modifier whenNotPaused() {
        require(!paused, "paused");
        _;
    }

    function registerMarket(uint256 marketId, address config) external whenNotPaused {
        require(config != address(0), "zero config");
        marketConfig[marketId] = config;
    }
}

contract AlternateUpgradeEntrypoint {
    address public governance;
    address public implementation;

    constructor(address initialGovernance) {
        governance = initialGovernance;
    }

    function upgradeTo(address newImplementation) external {
        require(msg.sender == governance, "not governance");
        implementation = newImplementation;
    }

    function upgradeToAndCall(address newImplementation, bytes calldata data) external {
        require(newImplementation != address(0), "zero implementation");
        implementation = newImplementation;
        if (data.length != 0) {
            (bool ok,) = newImplementation.delegatecall(data);
            require(ok, "delegatecall failed");
        }
    }
}

contract SettingsCallbackInjection {
    address public owner;
    address public settings;

    constructor(address initialOwner) {
        owner = initialOwner;
    }

    function updateSettings(address newSettings) external {
        require(newSettings != address(0), "zero settings");
        settings = newSettings;
    }
}
