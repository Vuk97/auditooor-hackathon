// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract Ownable {
    address public owner;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner, "NOT_OWNER"); _; }
}

/// CLEAN: every privileged setter rejects address(0) before writing. Mix of
/// idioms (require, if/revert, custom-error ZeroAddress) exercises each arm
/// of the pattern's negative regex.
contract SetterNoZeroValidationClean is Ownable {
    error ZeroAddress();

    address public treasury;
    address public oracle;
    address public router;
    address public strategy;
    address public guardian;
    address public implementation;
    address public paymaster;

    function setTreasury(address _t) external onlyOwner {
        require(_t != address(0), "zero address");
        treasury = _t;
    }

    function updateOracle(address _o) external onlyOwner {
        if (_o == address(0)) revert ZeroAddress();
        oracle = _o;
    }

    function changeRouter(address _r) external onlyOwner {
        require(_r != address(0), "zero address");
        router = _r;
    }

    function configureStrategy(address _s) external onlyOwner {
        if (_s == address(0)) revert ZeroAddress();
        strategy = _s;
    }

    function setGuardian(address _g) external onlyOwner {
        require(_g != address(0), "zero address");
        guardian = _g;
    }

    function setImplementation(address _i) external onlyOwner {
        require(_i != address(0), "zero address");
        implementation = _i;
    }

    function setPaymaster(address _p) external onlyOwner {
        require(_p != address(0), "zero address");
        paymaster = _p;
    }
}
