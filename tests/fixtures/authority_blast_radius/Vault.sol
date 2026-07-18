// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal self-contained OZ-style AccessControl (mirrors lido PausableUntilWithRoles
// role pattern: onlyRole(ROLE) guards + _grantRole + DEFAULT_ADMIN_ROLE).
abstract contract AccessControl {
    mapping(bytes32 => mapping(address => bool)) private _has;
    mapping(bytes32 => bytes32) private _adminOf;
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;

    modifier onlyRole(bytes32 role) {
        require(_has[role][msg.sender], "AC: denied");
        _;
    }

    function hasRole(bytes32 role, address a) public view returns (bool) {
        return _has[role][a];
    }

    function getRoleAdmin(bytes32 role) public view returns (bytes32) {
        return _adminOf[role];
    }

    function _grantRole(bytes32 role, address a) internal {
        _has[role][a] = true;
    }

    function _setRoleAdmin(bytes32 role, bytes32 adminRole) internal {
        _adminOf[role] = adminRole;
    }
}

contract Vault is AccessControl {
    bytes32 public constant BROAD_ROLE = keccak256("BROAD_ROLE");
    bytes32 public constant FEE_ROLE = keccak256("FEE_ROLE");
    bytes32 public constant POWERFUL_ROLE = keccak256("POWERFUL_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant CONFIG_ROLE = keccak256("CONFIG_ROLE");
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");
    bytes32 public constant ORACLE_ROLE = keccak256("ORACLE_ROLE");
    bytes32 public constant OWNER_ROLE = keccak256("OWNER_ROLE");

    bool public paused;
    uint256 public protocolFee;
    uint256 public performanceFee;
    uint256 public baseFee;
    address public oracle;
    address public owner;
    address public implementation;
    mapping(address => uint256) public balances;

    // BROAD_ROLE spans pause + fund-movement  -> BLAST-RADIUS flag.
    function pauseVault() external onlyRole(BROAD_ROLE) {
        paused = true;
    }

    function withdrawEmergency(address to, uint256 amt) external onlyRole(BROAD_ROLE) {
        balances[to] -= amt;
        payable(to).transfer(amt);
    }

    // FEE_ROLE spans only fee  -> benign, NO blast flag.
    function setProtocolFee(uint256 v) external onlyRole(FEE_ROLE) {
        protocolFee = v;
    }

    function setPerformanceFee(uint256 v) external onlyRole(FEE_ROLE) {
        performanceFee = v;
    }

    // POWERFUL_ROLE guards fund movement (power = 3).
    function withdrawTo(address to, uint256 amt) external onlyRole(POWERFUL_ROLE) {
        balances[to] -= amt;
        payable(to).transfer(amt);
    }

    // CONFIG_ROLE guards a single fee setter (power = 2).
    function setBaseFee(uint256 v) external onlyRole(CONFIG_ROLE) {
        baseFee = v;
    }

    // ORACLE_ROLE guards an oracle setter (power = 2).
    function setOracle(address o) external onlyRole(ORACLE_ROLE) {
        oracle = o;
    }

    // LIDO-STYLE FALSE-POSITIVE GUARD: OWNER_ROLE guards an ownership handover
    // + an implementation setter. transferOwnership's "transfer" name token
    // would spuriously bucket it into fund-movement, manufacturing a 2-class
    // span with setImplementation (owner-implementation) = the measured lido FP.
    // A3 DEFERS ownership handover to two-step-ownership, so after the exclusion
    // OWNER_ROLE spans only owner-implementation -> NO blast-radius flag.
    function transferOwnership(address a) external onlyRole(OWNER_ROLE) {
        owner = a;
    }

    function setImplementation(address impl) external onlyRole(OWNER_ROLE) {
        implementation = impl;
    }

    // PRIVILEGE-INVERSION: weak OPERATOR_ROLE (rank 1) grants POWERFUL_ROLE
    // (power 3) -> FLAG.
    function grantPowerful(address a) external onlyRole(OPERATOR_ROLE) {
        _grantRole(POWERFUL_ROLE, a);
    }

    // BENIGN grant: DEFAULT_ADMIN_ROLE (rank 3) grants CONFIG_ROLE (power 2)
    // -> NO flag.
    function grantConfig(address a) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(CONFIG_ROLE, a);
    }

    // BENIGN equality: MANAGER_ROLE (rank 2) grants ORACLE_ROLE (power 2)
    // -> NO flag (strictly-less predicate; a `<=` mutation would flag this).
    function grantOracleAdmin(address a) external onlyRole(MANAGER_ROLE) {
        _grantRole(ORACLE_ROLE, a);
    }

    receive() external payable {}
}
