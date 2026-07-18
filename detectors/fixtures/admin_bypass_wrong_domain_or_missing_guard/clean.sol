// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract GuardedRegistry {
    mapping(bytes32 => address) public adapters;
    address public owner;

    constructor(address initialOwner) {
        owner = initialOwner;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function setAdapter(bytes32 key, address adapter) external onlyOwner {
        require(adapter != address(0), "zero adapter");
        adapters[key] = adapter;
    }
}

contract FactoryBoundGateway {
    address public factory;
    address public gateway;

    constructor(address initialFactory) {
        factory = initialFactory;
    }

    function setGateway(address newGateway) external {
        require(msg.sender == factory, "not factory");
        gateway = newGateway;
    }
}

contract StoredAuthorityDomain {
    address public adminDomain;
    address public manager;

    constructor(address initialAdminDomain) {
        adminDomain = initialAdminDomain;
    }

    function changeManager(address newManager) external {
        require(IAdminDomainClean(adminDomain).hasRole(msg.sender), "not admin");
        manager = newManager;
    }
}

interface IAdminDomainClean {
    function hasRole(address account) external view returns (bool);
}

contract RoleGuardedMutation {
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    mapping(bytes32 => mapping(address => bool)) public roles;

    modifier onlyRole(bytes32 role) {
        require(roles[role][msg.sender], "missing role");
        _;
    }

    function grantOperator(address account) external onlyRole(OPERATOR_ROLE) {
        roles[OPERATOR_ROLE][account] = true;
    }
}

contract GovernanceGuardedMarketConfig {
    address public governance;
    bool public paused;
    mapping(uint256 => address) public marketConfig;

    constructor(address initialGovernance) {
        governance = initialGovernance;
    }

    modifier onlyGovernance() {
        require(msg.sender == governance, "not governance");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "paused");
        _;
    }

    function registerMarket(uint256 marketId, address config) external onlyGovernance whenNotPaused {
        require(config != address(0), "zero config");
        marketConfig[marketId] = config;
    }
}

contract GuardedUpgradeEntrypoint {
    address public governance;
    address public implementation;

    constructor(address initialGovernance) {
        governance = initialGovernance;
    }

    function upgradeToAndCall(address newImplementation, bytes calldata data) external {
        require(msg.sender == governance, "not governance");
        require(newImplementation != address(0), "zero implementation");
        implementation = newImplementation;
        if (data.length != 0) {
            (bool ok,) = newImplementation.delegatecall(data);
            require(ok, "delegatecall failed");
        }
    }
}

contract SelfServiceProfile {
    mapping(address => address) public preferredAdapter;

    function setPreferredAdapter(address adapter) external {
        require(adapter != address(0), "zero adapter");
        preferredAdapter[msg.sender] = adapter;
    }
}
