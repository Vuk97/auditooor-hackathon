// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// clean.sol - admin-bypass-umbrella
// CLEAN: All privileged setters are guarded by onlyOwner or equivalent.

contract CleanAdminGuarded {
    address public owner;
    address public feeRecipient;
    mapping(address => bool) public collateralEnabled;
    mapping(address => address) public oracleForToken;

    constructor(address _owner, address _feeRecipient) {
        owner = _owner;
        feeRecipient = _feeRecipient;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    // CLEAN: onlyOwner guard present on feeRecipient setter.
    function setFeeRecipient(address r) external onlyOwner {
        feeRecipient = r;
    }

    // CLEAN: onlyOwner guard present on collateral setter.
    function setCollateralEnabled(address asset, bool enabled) external onlyOwner {
        collateralEnabled[asset] = enabled;
    }

    // CLEAN: onlyOwner guard present on oracle setter.
    function setOracle(address token, address oracle) external onlyOwner {
        oracleForToken[token] = oracle;
    }

    // CLEAN: two-step ownership transfer to prevent frontrun and ensure safe handover.
    address public pendingOwner;

    function transferOwnership(address newOwner) external onlyOwner {
        pendingOwner = newOwner;
    }

    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "not pending owner");
        owner = pendingOwner;
        delete pendingOwner;
    }
}

contract CleanSelfService {
    mapping(address => string) public userProfile;
    mapping(address => bool) public notificationsEnabled;

    function setUserProfile(string calldata uri) external {
        userProfile[msg.sender] = uri;
    }

    function setNotificationPreference(bool enabled) external {
        notificationsEnabled[msg.sender] = enabled;
    }
}

contract CleanInitAndRoleGrant {
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    address public owner;
    mapping(bytes32 => mapping(address => bool)) public roles;

    modifier initializer() {
        require(owner == address(0), "already initialized");
        _;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function initialize(address newOwner) external initializer {
        owner = newOwner;
    }

    function grantRole(bytes32 role, address account) public onlyOwner {
        roles[role][account] = true;
    }
}

contract CleanAdminWrapper {
    address public owner;
    mapping(bytes4 => bool) public approvedSelector;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address _owner) {
        owner = _owner;
    }

    function setSelector(bytes4 selector, bool allowed) external onlyOwner {
        approvedSelector[selector] = allowed;
    }

    function executeAdmin(address target, bytes calldata data) external onlyOwner returns (bytes memory result) {
        require(approvedSelector[bytes4(data)], "selector blocked");
        (bool ok, bytes memory response) = target.delegatecall(data);
        require(ok, "call failed");
        return response;
    }
}

contract CleanSignatureAuthorizedAdminWrite {
    address public owner;
    address public controller;
    mapping(bytes32 => bool) public usedDigests;

    constructor(address _owner) {
        owner = _owner;
    }

    function authorizeControllerBySig(
        address newController,
        string calldata scope,
        bytes calldata extraData,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 digest = keccak256(abi.encode(scope, extraData, newController));
        address signer = ecrecover(digest, v, r, s);
        require(signer == owner, "bad sig");
        require(!usedDigests[digest], "used");
        usedDigests[digest] = true;
        controller = newController;
    }
}

contract CleanBlacklistForceOperation {
    mapping(address => bool) public blacklist;
    mapping(address => uint256) public collateral;

    function setBlacklist(address account, bool blocked) external {
        blacklist[account] = blocked;
    }

    function repayBorrow(address borrower, uint256 amount) external {
        require(!blacklist[borrower], "blocked");
        collateral[borrower] -= amount;
    }

    function coverAccount(address borrower, uint256 amount) external {
        require(!blacklist[borrower], "blocked");
        collateral[borrower] -= amount;
    }
}
