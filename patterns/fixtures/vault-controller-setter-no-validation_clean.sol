// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract Ownable {
    address public owner;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner, "NOT_OWNER"); _; }
}

/// CLEAN: every privileged setter either validates zero-address or routes
/// through a two-step pending/accept handshake.
contract VaultConfigClean is Ownable {
    address public controller;
    address public treasury;
    address public priceOracle;
    address public feeReceiver;
    address public strategy;

    address public pendingController;

    // CLEAN: zero-address rejection before write.
    function setTreasury(address _t) external onlyOwner {
        require(_t != address(0), "ZERO_ADDR");
        treasury = _t;
    }

    function setOracle(address _o) external onlyOwner {
        require(_o != address(0), "ZERO_ADDR");
        priceOracle = _o;
    }

    function setFeeReceiver(address _r) external onlyOwner {
        require(_r != address(0), "ZERO_ADDR");
        feeReceiver = _r;
    }

    function setStrategy(address _s) external onlyOwner {
        require(_s != address(0), "ZERO_ADDR");
        strategy = _s;
    }

    // CLEAN: two-step handshake for the most critical rotation.
    function setController(address _c) external onlyOwner {
        require(_c != address(0), "ZERO_ADDR");
        pendingController = _c;
    }

    function acceptController() external {
        require(msg.sender == pendingController, "NOT_PENDING");
        controller = pendingController;
        pendingController = address(0);
    }
}
