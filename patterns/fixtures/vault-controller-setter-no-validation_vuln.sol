// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract Ownable {
    address public owner;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner, "NOT_OWNER"); _; }
}

/// VULN: every privileged setter writes the new address with no zero-address
/// validation and no two-step handshake. Any fat-fingered governance
/// transaction permanently misconfigures the protocol wiring.
contract VaultConfigVuln is Ownable {
    address public controller;
    address public treasury;
    address public priceOracle;
    address public feeReceiver;
    address public strategy;

    // VULN: no require(_c != address(0)), no pendingController handshake.
    function setController(address _c) external onlyOwner {
        controller = _c;
    }

    // VULN: same pattern — treasury swap with no validation.
    function setTreasury(address _t) external onlyOwner {
        treasury = _t;
    }

    // VULN: oracle manager rotation with no validation.
    function setOracle(address _o) external onlyOwner {
        priceOracle = _o;
    }

    // VULN: fee receiver with no validation.
    function setFeeReceiver(address _r) external onlyOwner {
        feeReceiver = _r;
    }

    // VULN: strategy router with no validation.
    function setStrategy(address _s) external onlyOwner {
        strategy = _s;
    }
}
