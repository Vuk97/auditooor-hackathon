// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// positive.sol - admin-bypass-umbrella
// VULN: Privileged setters with no caller restriction.
// Subshape A: setFeeRecipient is permissionless
// Subshape B: setCollateralEnabled with no guard (aave isolated market shape)
// Subshape C: setOracle with no guard
// Subshape D: public ownership setup and role self-grant
// Subshape E: wrong authority domain and admin operation routed through a permissionless wrapper
// Subshape F: collision-prone signature auth gates a privileged controller write
// Subshape G: blacklist enforced on the normal path but skipped on a force-operation path

contract VulnAdminBypass {
    address public owner;
    address public feeRecipient;
    mapping(address => bool) public collateralEnabled;
    mapping(address => address) public oracleForToken;

    constructor(address _owner, address _feeRecipient) {
        owner = _owner;
        feeRecipient = _feeRecipient;
    }

    // VULN subshape A: unrestricted privileged feeRecipient setter.
    // Any caller can redirect protocol fees to their address.
    function setFeeRecipient(address r) external {
        feeRecipient = r;
    }

    // VULN subshape B: collateral enable bypass - no admin modifier
    // Any caller can enable isolated collateral modes that should only be admin-settable.
    function setCollateralEnabled(address asset, bool enabled) external {
        collateralEnabled[asset] = enabled;
    }

    // VULN subshape C: oracle manipulation with no caller restriction.
    // Any caller can point oracle to a manipulated price source.
    function setOracle(address token, address oracle) external {
        oracleForToken[token] = oracle;
    }
}

// Second shape: settings contract injection
// Attacker can inject a malicious settings contract that triggers onOwnershipTransferred callback.
interface ISettings {
    function onOwnershipTransferred(address previousOwner, address newOwner) external;
}

contract VulnSettingsInjection {
    address public owner;
    ISettings public settings;

    constructor(address _owner) {
        owner = _owner;
    }

    // VULN: no caller restriction on settings setter - attacker injects malicious settings contract.
    function updateSettings(address _settings) external {
        settings = ISettings(_settings);
    }

    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "not owner");
        address prev = owner;
        owner = newOwner;
        if (address(settings) != address(0)) {
            settings.onOwnershipTransferred(prev, newOwner);
        }
    }
}

contract VulnInitAndRoleGrant {
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    address public owner;
    mapping(bytes32 => mapping(address => bool)) public roles;

    function initialize(address newOwner) external {
        owner = newOwner;
    }

    function grantRole(bytes32 role, address account) public {
        roles[role][account] = true;
    }

    function grantOperatorToSelf() external {
        grantRole(OPERATOR_ROLE, msg.sender);
    }
}

contract VulnAdminWrapper {
    address public owner;
    address public controller;
    mapping(bytes4 => bool) public approvedSelector;

    constructor(address _owner) {
        owner = _owner;
    }

    function setController(address newController) external {
        require(tx.origin == owner, "wrong domain");
        controller = newController;
    }

    function setSelector(bytes4 selector, bool allowed) external {
        approvedSelector[selector] = allowed;
    }

    function executeAdmin(address target, bytes calldata data) external returns (bytes memory result) {
        (bool ok, bytes memory response) = target.delegatecall(data);
        require(ok, "call failed");
        return response;
    }
}

contract VulnSignatureAuthorizedAdminWrite {
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
        bytes32 digest = keccak256(abi.encodePacked(scope, extraData, newController));
        address signer = ecrecover(digest, v, r, s);
        require(signer == owner, "bad sig");
        require(!usedDigests[digest], "used");
        usedDigests[digest] = true;
        controller = newController;
    }
}

contract VulnBlacklistForceOperationBypass {
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
        collateral[borrower] -= amount;
    }
}
