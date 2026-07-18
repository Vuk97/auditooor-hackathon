// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract Ownable {
    address public owner;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner, "NOT_OWNER"); _; }
}

/// VULN: privileged setters for named protocol roles (treasury, oracle,
/// router, strategy, guardian, implementation, paymaster) accept an
/// address parameter and write it to storage with NO zero-address guard.
/// All are admin-gated via onlyOwner, so only governance (or a compromised
/// multisig / fat-fingered proposal) can trigger — but one miskeyed input
/// silently bricks the slot.
contract SetterNoZeroValidationVuln is Ownable {
    address public treasury;
    address public oracle;
    address public router;
    address public strategy;
    address public guardian;
    address public implementation;
    address public paymaster;

    // VULN: no require(_t != address(0))
    function setTreasury(address _t) external onlyOwner {
        treasury = _t;
    }

    // VULN: update-family setter, same bug.
    function updateOracle(address _o) external onlyOwner {
        oracle = _o;
    }

    // VULN: change-family setter, same bug.
    function changeRouter(address _r) external onlyOwner {
        router = _r;
    }

    // VULN: configure-family setter, same bug.
    function configureStrategy(address _s) external onlyOwner {
        strategy = _s;
    }

    // VULN: guardian rotation — particularly dangerous zero-address write.
    function setGuardian(address _g) external onlyOwner {
        guardian = _g;
    }

    // VULN: implementation slot (proxy upgrade target) with no zero guard.
    function setImplementation(address _i) external onlyOwner {
        implementation = _i;
    }

    // VULN: paymaster wiring (ERC-4337) with no zero guard.
    function setPaymaster(address _p) external onlyOwner {
        paymaster = _p;
    }
}
